import os
import urllib.parse
import requests
import asyncio
import threading
import discord
import base64
import io

from discord.ext import tasks, commands
from flask import (
    Flask, redirect, url_for, session,
    render_template, request, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

# ----------------- НАСТРОЙКИ FLASK -----------------
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'very_secret_key_change_me')

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'court.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ----------------- КОНФИГ DISCORD -----------------
GUILD_ID = int(os.getenv('GUILD_ID', '1468002775471226896'))

CLIENT_ID = os.getenv('DISCORD_CLIENT_ID', '1468026057356480674')
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET', 'REPLACE_ME')
REDIRECT_URI = os.getenv('REDIRECT_URI', 'https://your-render-url.onrender.com/callback')
TOKEN = os.getenv('DISCORD_TOKEN', 'REPLACE_ME_BOT_TOKEN')

WEBHOOK_URL = os.getenv(
    'WEBHOOK_URL',
    "https://discord.com/api/webhooks/XXX/YYY"  # замени на свой
)

# КАРТА: ID роли в Discord -> текстовая роль на сайте
ROLE_MAP = {
    '1468030929120399501': 'Председатель Верховного Суда',
    '1468030940973498398': 'Верховный Судья',
    '1468030941040738344': 'Кассационный судья',
    '1468030941615226931': 'Судья по Уголовным и Административным делам',
    '1468030942231793795': 'Судья по гражданским делам'
}

# Префиксы для разных судов
COURT_PREFIXES = {
    'Кассационный суд': 'KA',
    'Верховный суд': 'GH',  # совместно для ПВС и ВС
    'Председатель Верховного Суда': 'GH',
    'Верховный Судья': 'GH',
    'Суд по Уголовным и Административным делам': 'YD',
    'Суд по гражданским делам': 'GK'
}


# ----------------- МОДЕЛИ БД -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(100))
    role = db.Column(db.String(100), default='Гражданин')


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_num = db.Column(db.String(50), unique=True)  # например GK-001
    court_type = db.Column(db.String(100))            # тип суда (человеческий текст)
    prefix = db.Column(db.String(10))                 # GK, KA, ...
    image_data = db.Column(db.Text)                   # PNG base64
    author_id = db.Column(db.String(50))              # discord_id автора
    judge_id = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), default='Новый')
    result = db.Column(db.Text, nullable=True)
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class DiscordQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50))
    role_name = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')


# ----------------- DISCORD БОТ -----------------
intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)


@tasks.loop(seconds=10)
async def check_queue():
    """Каждые 10 секунд обрабатываем очередь на выдачу ролей дел."""
    with app.app_context():
        tasks_to_do = DiscordQueue.query.filter_by(status='pending').all()
        if not tasks_to_do:
            return

        guild = bot.get_guild(GUILD_ID)
        if not guild:
            return

        for task in tasks_to_do:
            try:
                member = await guild.fetch_member(int(task.discord_id))
                role = discord.utils.get(guild.roles, name=task.role_name)
                if role is None:
                    role = await guild.create_role(name=task.role_name)
                await member.add_roles(role)
                task.status = 'done'
            except Exception as e:
                print(f"Ошибка выдачи роли Discord: {e}")
                task.status = 'error'
        db.session.commit()


@bot.event
async def on_ready():
    print(f"Бот авторизован как {bot.user}")
    if not check_queue.is_running():
        check_queue.start()


# ----------------- ХЕЛПЕРЫ -----------------
def get_auth_url():
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds.members.read"
    }
    return "https://discord.com/api/oauth2/authorize?" + urllib.parse.urlencode(params)


def get_or_create_user(discord_user_id, display_name, user_role):
    user = User.query.filter_by(discord_id=discord_user_id).first()
    if not user:
        user = User(discord_id=discord_user_id, username=display_name, role=user_role)
        db.session.add(user)
    else:
        user.username = display_name
        user.role = user_role
    db.session.commit()
    return user


def define_site_role(member_roles):
    """Определяем роль на сайте по ролям Discord."""
    for rid in member_roles:
        if rid in ROLE_MAP:
            return ROLE_MAP[rid]
    return 'Гражданин'


def get_prefix_for_court(court_name: str) -> str:
    """Возвращаем префикс дела по типу суда."""
    return COURT_PREFIXES.get(court_name, 'GK')  # по умолчанию GK


def generate_case_number(prefix: str) -> str:
    """
    Ищем в БД максимальный номер с данным префиксом
    и увеличиваем на 1: GK-001, GK-002 и т.д.
    """
    last_case = Case.query.filter_by(prefix=prefix).order_by(Case.id.desc()).first()
    if not last_case:
        next_num = 1
    else:
        # last_case.case_num = "GK-001"
        try:
            parts = last_case.case_num.split('-')
            if len(parts) == 2:
                last_number = int(parts[1])
                next_num = last_number + 1
            else:
                next_num = 1
        except Exception:
            next_num = 1

    return f"{prefix}-{next_num:03d}"


def get_cases_for_user(user: User):
    """Фильтрация дел, чтобы гражданин не видел чужие иски."""
    q = Case.query.order_by(Case.date.desc())

    # Гражданин: только свои дела
    if user.role == 'Гражданин':
        return q.filter_by(author_id=user.discord_id).all()

    # Судьи: видят дела по своей категории
    # Карта: роль на сайте -> префикс
    role_prefix_map = {
        'Кассационный судья': 'KA',
        'Председатель Верховного Суда': 'GH',
        'Верховный Судья': 'GH',
        'Судья по Уголовным и Административным делам': 'YD',
        'Судья по гражданским делам': 'GK'
    }

    if user.role in role_prefix_map:
        pref = role_prefix_map[user.role]
        return q.filter_by(prefix=pref).all()

    # На всякий случай: по умолчанию — только свои
    return q.filter_by(author_id=user.discord_id).all()


# ----------------- ROUTES -----------------
@app.route('/')
def index():
    if 'user_id' not in session:
        auth_url = get_auth_url()
        return render_template('login.html', auth_url=auth_url)

    user = User.query.filter_by(discord_id=session['user_id']).first()
    if not user:
        session.clear()
        auth_url = get_auth_url()
        return render_template('login.html', auth_url=auth_url)

    cases = get_cases_for_user(user)

    # Типы судов для формы (гражданин выбирает руками)
    court_options = [
        "Верховный суд",
        "Кассационный суд",
        "Суд по Уголовным и Административным делам",
        "Суд по гражданским делам"
    ]

    return render_template(
        'index.html',
        user=user,
        cases=cases,
        court_options=court_options
    )


@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Code not provided", 400

    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    r = requests.post("https://discord.com/api/v10/oauth2/token", data=data)
    token_data = r.json()

    access_token = token_data.get('access_token')
    if not access_token:
        return "Authorization failed", 400

    headers = {"Authorization": f"Bearer {access_token}"}
    u_info = requests.get("https://discord.com/api/v10/users/@me", headers=headers).json()
    m_info = requests.get(
        f"https://discord.com/api/v10/users/@me/guilds/{GUILD_ID}/member",
        headers=headers
    ).json()

    # Ник/имя
    display_name = (
        m_info.get('nick')
        or u_info.get('global_name')
        or u_info.get('username')
    )

    # Определяем роль сайта по ролям Discord
    discord_roles = m_info.get('roles', [])
    user_role = define_site_role(discord_roles)

    user = get_or_create_user(u_info['id'], display_name, user_role)

    session['user_id'] = u_info['id']
    return redirect(url_for('index'))


@app.route('/save_case_image', methods=['POST'])
def save_case_image():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json
    img_base64 = data.get('image')
    court_type = data.get('court_type')

    if not img_base64 or not court_type:
        return jsonify({"status": "error", "message": "No image or court type"}), 400

    user = User.query.filter_by(discord_id=session['user_id']).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    prefix = get_prefix_for_court(court_type)
    case_num = generate_case_number(prefix)

    new_case = Case(
        case_num=case_num,
        court_type=court_type,
        prefix=prefix,
        image_data=img_base64,
        author_id=session['user_id'],
        status='Новый'
    )
    db.session.add(new_case)

    # Очередь на выдачу роли с номером дела
    db.session.add(DiscordQueue(
        discord_id=session['user_id'],
        role_name=case_num
    ))

    db.session.commit()

    # Отправка в вебхук
    try:
        header, encoded = img_base64.split(",", 1)
        binary_data = base64.b64decode(encoded)
        files = {
            'file': ('claim.png', io.BytesIO(binary_data), 'image/png')
        }
        payload = {
            "content": (
                f"⚖️ **ЗАРЕГИСТРИРОВАНО НОВОЕ ИСКОВОЕ ЗАЯВЛЕНИЕ {case_num}**\n"
                f"**Суд:** {court_type}\n"
                f"**Отправитель:** <@{session['user_id']}>"
            )
        }
        requests.post(WEBHOOK_URL, data=payload, files=files)
    except Exception as e:
        print(f"Ошибка при отправке вебхука: {e}")

    return jsonify({"status": "success", "case_num": case_num})


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


def run_bot():
    asyncio.run(bot.start(TOKEN))


# ----------------- START -----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    threading.Thread(target=run_bot, daemon=True).start()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
