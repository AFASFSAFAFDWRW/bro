import os
import urllib.parse
import requests
import asyncio
import threading
import discord
import base64
import io
import secrets
import time

from discord.ext import tasks, commands
from flask import (
    Flask, redirect, url_for, session,
    render_template, request, jsonify, abort
)
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

# ----------------- НАСТРОЙКИ FLASK -----------------
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change_me')

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'court.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ----------------- КОНФИГ DISCORD -----------------
GUILD_ID = int(os.getenv('GUILD_ID', '1468002775471226896'))

CLIENT_ID = os.getenv('DISCORD_CLIENT_ID', '1468026057356480674')
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET', 'REPLACE_ME')
REDIRECT_URI = os.getenv('REDIRECT_URI', 'https://bro-4nhb.onrender.com/callback')
TOKEN = os.getenv('DISCORD_TOKEN', 'REPLACE_ME_BOT_TOKEN')

WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')

ROLE_MAP = {
    '1468030929120399501': 'Председатель Верховного Суда',
    '1468030940973498398': 'Верховный Судья',
    '1468030941040738344': 'Кассационный судья',
    '1468030941615226931': 'Судья по Уголовным и Административным делам',
    '1468030942231793795': 'Судья по гражданским делам'
}

COURT_PREFIXES = {
    'Верховный Суд': 'GH',
    'Кассационный Суд': 'KA',
    'Суд по Уголовным делам': 'YD',
    'Суд по Административным делам': 'YD',
    'Суд по гражданским делам': 'GK',
}

CASE_STATUSES = [
    "Новый",
    "Принят",
    "Назначен судья",
    "На рассмотрении",
    "Решение вынесено",
    "Закрыт"
]

# ----------------- МОДЕЛИ -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(100))
    role = db.Column(db.String(100), default='Гражданин')


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_num = db.Column(db.String(50), unique=True)
    court_type = db.Column(db.String(100))
    prefix = db.Column(db.String(10))
    image_data = db.Column(db.Text)

    # автор и назначенный судья
    author_id = db.Column(db.String(50))
    judge_id = db.Column(db.String(50), nullable=True)

    status = db.Column(db.String(50), default='Новый')
    result = db.Column(db.Text, nullable=True)

    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class DiscordQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50))
    role_name = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')


class DiscordMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(100))
    roles = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class RolePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.String(50), unique=True)
    role_name = db.Column(db.String(100))
    can_close_cases = db.Column(db.Boolean, default=False)
    can_view_all_cases = db.Column(db.Boolean, default=False)
    can_create_cases = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# ----------------- ПРОСТОЙ RATE LIMIT -----------------
_last_calls = {}
def rate_limit(key: str, seconds: int = 2):
    now = time.time()
    prev = _last_calls.get(key, 0)
    if now - prev < seconds:
        return False
    _last_calls[key] = now
    return True


# ----------------- DISCORD BOT -----------------
intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

@tasks.loop(seconds=10)
async def check_queue():
    with app.app_context():
        items = DiscordQueue.query.filter_by(status='pending').all()
        if not items:
            return
        guild = bot.get_guild(GUILD_ID)
        if not guild:
            return
        for task in items:
            try:
                member = await guild.fetch_member(int(task.discord_id))
                role = discord.utils.get(guild.roles, name=task.role_name)
                if role is None:
                    role = await guild.create_role(name=task.role_name)
                await member.add_roles(role)
                task.status = 'done'
            except Exception as e:
                print("queue error:", e)
                task.status = 'error'
        db.session.commit()

@tasks.loop(seconds=10)
async def sync_members():
    with app.app_context():
        guild = bot.get_guild(GUILD_ID)
        if not guild:
            return
        try:
            async for member in guild.fetch_members(limit=None):
                role_names = [r.name for r in member.roles if r.name != "@everyone"]
                roles_str = ",".join(role_names)
                m = DiscordMember.query.filter_by(discord_id=str(member.id)).first()
                if not m:
                    m = DiscordMember(discord_id=str(member.id), username=member.display_name, roles=roles_str)
                    db.session.add(m)
                else:
                    m.username = member.display_name
                    m.roles = roles_str
                    m.updated_at = datetime.now(timezone.utc)
            db.session.commit()
        except Exception as e:
            print("sync_members error:", e)

@bot.event
async def on_ready():
    print("Bot ready:", bot.user)
    if not check_queue.is_running():
        check_queue.start()
    if not sync_members.is_running():
        sync_members.start()


# ----------------- HELPERS -----------------
def get_auth_url():
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds.members.read"
    }
    return "https://discord.com/api/oauth2/authorize?" + urllib.parse.urlencode(params)

def current_user():
    if 'user_id' not in session:
        return None
    return User.query.filter_by(discord_id=session['user_id']).first()

def define_site_role(discord_role_ids):
    for rid in discord_role_ids:
        if rid in ROLE_MAP:
            return ROLE_MAP[rid]
    return "Гражданин"

def get_prefix_for_court(court_type: str) -> str:
    return COURT_PREFIXES.get(court_type, "GK")

def generate_case_number(prefix: str) -> str:
    last = Case.query.filter_by(prefix=prefix).order_by(Case.id.desc()).first()
    if not last:
        n = 1
    else:
        try:
            n = int(last.case_num.split("-")[1]) + 1
        except Exception:
            n = 1
    return f"{prefix}-{n:03d}"

def is_pvs(user: User) -> bool:
    return user and user.role == "Председатель Верховного Суда"

def get_role_permissions_map():
    perms = RolePermission.query.all()
    return {p.role_id: p for p in perms}

def user_virtual_perms(discord_id: str):
    """
    Суммарные виртуальные права по ролям Discord.
    """
    res = {"can_close_cases": False, "can_view_all_cases": False, "can_create_cases": True}
    guild = bot.get_guild(GUILD_ID)
    if not guild:
        return res

    perms_map = get_role_permissions_map()
    try:
        member = asyncio.run_coroutine_threadsafe(guild.fetch_member(int(discord_id)), bot.loop).result()
    except Exception:
        return res

    for r in member.roles:
        p = perms_map.get(str(r.id))
        if not p:
            continue
        if p.can_close_cases:
            res["can_close_cases"] = True
        if p.can_view_all_cases:
            res["can_view_all_cases"] = True
        if not p.can_create_cases:
            res["can_create_cases"] = False
    return res

def can_view_case(user: User, case: Case) -> bool:
    if not user:
        return False
    perms = user_virtual_perms(user.discord_id)
    if perms["can_view_all_cases"]:
        return True
    if case.author_id == user.discord_id:
        return True
    # судья видит дела своего типа (по префиксу) + если он назначен
    role_prefix_map = {
        'Кассационный судья': 'KA',
        'Председатель Верховного Суда': 'GH',
        'Верховный Судья': 'GH',
        'Судья по Уголовным и Административным делам': 'YD',
        'Судья по гражданским делам': 'GK'
    }
    pref = role_prefix_map.get(user.role)
    if pref and pref == case.prefix:
        return True
    if case.judge_id and case.judge_id == user.discord_id:
        return True
    return False

def get_cases_for_user(user: User):
    q = Case.query.order_by(Case.date.desc())
    perms = user_virtual_perms(user.discord_id)
    if perms["can_view_all_cases"]:
        return q.all()
    if user.role == "Гражданин":
        return q.filter_by(author_id=user.discord_id).all()

    role_prefix_map = {
        'Кассационный судья': 'KA',
        'Председатель Верховного Суда': 'GH',
        'Верховный Судья': 'GH',
        'Судья по Уголовным и Административным делам': 'YD',
        'Судья по гражданским делам': 'GK'
    }
    pref = role_prefix_map.get(user.role)
    if pref:
        return q.filter_by(prefix=pref).all()
    return q.filter_by(author_id=user.discord_id).all

def ensure_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)

def check_csrf():
    token = request.headers.get("X-CSRF")
    return token and session.get("csrf") and token == session.get("csrf")


# ----------------- ROUTES -----------------
@app.route("/")
def index():
    if "user_id" not in session:
        return render_template("login.html", auth_url=get_auth_url())

    user = current_user()
    if not user:
        session.clear()
        return render_template("login.html", auth_url=get_auth_url())

    ensure_csrf()
    cases = get_cases_for_user(user)
    return render_template("index.html", user=user, cases=cases, csrf=session["csrf"])


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Code not provided", 400

    token_data = requests.post("https://discord.com/api/v10/oauth2/token", data={
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI
    }).json()

    access_token = token_data.get("access_token")
    if not access_token:
        return "Authorization failed", 400

    headers = {"Authorization": f"Bearer {access_token}"}
    u_info = requests.get("https://discord.com/api/v10/users/@me", headers=headers).json()
    m_info = requests.get(
        f"https://discord.com/api/v10/users/@me/guilds/{GUILD_ID}/member",
        headers=headers
    ).json()

    display_name = (m_info.get("nick") or u_info.get("global_name") or u_info.get("username"))
    user_role = define_site_role(m_info.get("roles", []))

    user = User.query.filter_by(discord_id=u_info["id"]).first()
    if not user:
        user = User(discord_id=u_info["id"], username=display_name, role=user_role)
        db.session.add(user)
    else:
        user.username = display_name
        user.role = user_role
    db.session.commit()

    session["user_id"] = u_info["id"]
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/case/<case_num>")
def view_case(case_num):
    user = current_user()
    if not user:
        return redirect("/")
    case = Case.query.filter_by(case_num=case_num).first_or_404()
    if not can_view_case(user, case):
        return "Доступ запрещён", 403

    ensure_csrf()
    perms = user_virtual_perms(user.discord_id)
    # можно менять, если ПВС или есть право закрывать
    can_manage = is_pvs(user) or perms["can_close_cases"]
    return render_template("case.html", user=user, case=case, can_manage=can_manage,
                           statuses=CASE_STATUSES, csrf=session["csrf"])


@app.route("/api/case/update", methods=["POST"])
def api_case_update():
    user = current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    if not check_csrf():
        return jsonify({"error": "csrf"}), 403
    if not rate_limit(f"case_update:{user.discord_id}", 1):
        return jsonify({"error": "rate_limited"}), 429

    data = request.get_json(silent=True) or {}
    case_num = data.get("case_num")
    status = data.get("status")
    result = data.get("result")

    case = Case.query.filter_by(case_num=case_num).first()
    if not case:
        return jsonify({"error": "not_found"}), 404
    if not can_view_case(user, case):
        return jsonify({"error": "forbidden"}), 403

    perms = user_virtual_perms(user.discord_id)
    if not (is_pvs(user) or perms["can_close_cases"]):
        return jsonify({"error": "no_permission"}), 403

    if status and status in CASE_STATUSES:
        case.status = status
    if result is not None:
        case.result = result

    db.session.commit()
    return jsonify({"result": "ok"})


@app.route("/api/case/assign_judge", methods=["POST"])
def api_assign_judge():
    user = current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    if not check_csrf():
        return jsonify({"error": "csrf"}), 403
    if not is_pvs(user):
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    case_num = data.get("case_num")
    judge_id = data.get("judge_id")  # discord id

    case = Case.query.filter_by(case_num=case_num).first()
    if not case:
        return jsonify({"error": "not_found"}), 404

    case.judge_id = judge_id
    case.status = "Назначен судья"
    db.session.commit()
    return jsonify({"result": "ok"})


@app.route("/save_case_image", methods=["POST"])
def save_case_image():
    if "user_id" not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    if not check_csrf():
        return jsonify({"status": "error", "message": "CSRF"}), 403

    data = request.get_json(silent=True) or {}
    img_base64 = data.get("image")
    court_type = data.get("court_type")

    if not img_base64 or not court_type:
        return jsonify({"status": "error", "message": "No image or court type"}), 400

    user = current_user()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    perms = user_virtual_perms(user.discord_id)
    if not perms["can_create_cases"]:
        return jsonify({"status": "error", "message": "Создание дел запрещено"}), 403

    prefix = get_prefix_for_court(court_type)
    case_num = generate_case_number(prefix)

    new_case = Case(
        case_num=case_num,
        court_type=court_type,
        prefix=prefix,
        image_data=img_base64,
        author_id=session["user_id"],
        status="Новый"
    )
    db.session.add(new_case)
    db.session.add(DiscordQueue(discord_id=session["user_id"], role_name=case_num))
    db.session.commit()

    # webhook
    if WEBHOOK_URL:
        try:
            header, encoded = img_base64.split(",", 1)
            binary_data = base64.b64decode(encoded)
            files = {'file': ('claim.png', io.BytesIO(binary_data), 'image/png')}
            link = f"{request.host_url.rstrip('/')}/case/{case_num}"
            payload = {
                "content": (
                    f"⚖️ **НОВОЕ ДЕЛО {case_num}**\n"
                    f"**Суд:** {court_type}\n"
                    f"**От:** <@{session['user_id']}>\n"
                    f"**Ссылка:** {link}"
                )
            }
            requests.post(WEBHOOK_URL, data=payload, files=files, timeout=10)
        except Exception as e:
            print("webhook error:", e)

    return jsonify({"status": "success", "case_num": case_num})


# --------- Админка ПВС (роль/права) оставляем как у тебя ---------
@app.route('/admin')
def admin_panel():
    user = current_user()
    if not user or not is_pvs(user):
        return "Доступ запрещён", 403
    ensure_csrf()
    return render_template('admin.html', user=user, csrf=session["csrf"])


@app.route('/api/members')
def api_members():
    user = current_user()
    if not user or not is_pvs(user):
        return jsonify({"error": "forbidden"}), 403
    members = DiscordMember.query.order_by(DiscordMember.username.asc()).all()
    data = [{"discord_id": m.discord_id, "username": m.username, "roles": (m.roles.split(",") if m.roles else [])} for m in members]
    return jsonify(data)


@app.route('/api/roles')
def api_roles():
    user = current_user()
    if not user or not is_pvs(user):
        return jsonify({"error": "forbidden"}), 403

    guild = bot.get_guild(GUILD_ID)
    if not guild:
        return jsonify([])

    perms_map = get_role_permissions_map()
    roles = []
    for r in sorted(guild.roles, key=lambda r: r.position, reverse=True):
        if r.name == "@everyone":
            continue
        p = perms_map.get(str(r.id))
        roles.append({
            "id": r.id,
            "name": r.name,
            "position": r.position,
            "can_close_cases": bool(p.can_close_cases) if p else False,
            "can_view_all_cases": bool(p.can_view_all_cases) if p else False,
            "can_create_cases": bool(p.can_create_cases) if p else True
        })
    return jsonify(roles)


@app.route('/api/set_role', methods=['POST'])
def api_set_role():
    user = current_user()
    if not user or not is_pvs(user):
        return jsonify({"error": "forbidden"}), 403
    if not check_csrf():
        return jsonify({"error": "csrf"}), 403

    data = request.get_json(silent=True) or {}
    discord_id = data.get('discord_id')
    role_id = data.get('role_id')
    action = data.get('action')
    if not discord_id or not role_id or action not in ('add', 'remove'):
        return jsonify({"error": "bad_request"}), 400

    async def do():
        guild = bot.get_guild(GUILD_ID)
        if not guild:
            return "guild_not_found"
        try:
            member = await guild.fetch_member(int(discord_id))
            role = guild.get_role(int(role_id))
            if not role:
                return "role_not_found"
            if action == 'add':
                await member.add_roles(role, reason="ПВС панель")
            else:
                await member.remove_roles(role, reason="ПВС панель")
            return "ok"
        except Exception as e:
            print("set_role error:", e)
            return "error"

    fut = asyncio.run_coroutine_threadsafe(do(), bot.loop)
    return jsonify({"result": fut.result()})


@app.route('/api/role_permissions', methods=['POST'])
def api_role_permissions():
    user = current_user()
    if not user or not is_pvs(user):
        return jsonify({"error": "forbidden"}), 403
    if not check_csrf():
        return jsonify({"error": "csrf"}), 403

    data = request.get_json(silent=True) or {}
    role_id = data.get('role_id')
    role_name = data.get('role_name') or ''
    if not role_id:
        return jsonify({"error": "bad_request"}), 400

    rp = RolePermission.query.filter_by(role_id=str(role_id)).first()
    if not rp:
        rp = RolePermission(role_id=str(role_id), role_name=role_name)
        db.session.add(rp)

    rp.role_name = role_name
    rp.can_close_cases = bool(data.get('can_close_cases'))
    rp.can_view_all_cases = bool(data.get('can_view_all_cases'))
    rp.can_create_cases = bool(data.get('can_create_cases'))
    rp.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({"result": "ok"})


def run_bot():
    asyncio.run(bot.start(TOKEN))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    threading.Thread(target=run_bot, daemon=True).start()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
