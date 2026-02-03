import os
import urllib.parse
import requests
import asyncio
import threading
import discord
from discord.ext import tasks, commands
from flask import Flask, redirect, url_for, session, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'rfgerfgdfgvds')

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'court.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- КОНФИГ ---
GUILD_ID = int(os.getenv('GUILD_ID', '1468002775471226896'))
CLIENT_ID = '1468026057356480674'
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET', '7rOUeCkC1x2KMEvmoeqJ8aP7uDZbgbgi')
REDIRECT_URI = os.getenv('REDIRECT_URI', 'https://bro-4nhb.onrender.com/callback')
TOKEN = os.getenv('DISCORD_TOKEN')
WEBHOOK_URL = "https://discord.com/api/webhooks/1468291063738400975/us9TPewLe-BDUgRtAq56rSJD6m7jiC5tD-QB7Tjsb-pBSIOdpFaiIig0cofHPCetMfJN"

ROLE_MAP = {
    '1468030929120399501': 'Председатель Верховного Суда',
    '1468030940973498398': 'Верховный Судья',
    '1468030941040738344': 'Кассационный судья',
    '1468030941615226931': 'Судья по Уголовным и Административным делам',
    '1468030942231793795': 'Судья по гражданским делам'
}

# --- МОДЕЛИ ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(100))
    role = db.Column(db.String(100), default='Гражданин')

class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_num = db.Column(db.String(20), unique=True)
    case_type = db.Column(db.String(10)) 
    author_id = db.Column(db.String(50))
    judge_id = db.Column(db.String(50), nullable=True) 
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    result = db.Column(db.Text, nullable=True) 
    status = db.Column(db.String(20), default='Новый')
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class DiscordQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50))
    role_name = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')

# --- ФУНКЦИЯ ВЕБХУКА ---
def send_discord_log(title, description, color=0x1a237e):
    # Теперь вебхук работает без блокировок
    try:
        data = {
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }]
        }
        requests.post(WEBHOOK_URL, json=data)
    except Exception as e:
        print(f"Ошибка вебхука: {e}")

# --- ЛОГИКА БОТА ---
intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

@tasks.loop(seconds=10)
async def check_queue():
    with app.app_context():
        tasks_to_do = DiscordQueue.query.filter_by(status='pending').all()
        guild = bot.get_guild(GUILD_ID)
        if not guild or not tasks_to_do: return
        for task in tasks_to_do:
            try:
                member = await guild.fetch_member(int(task.discord_id))
                role = discord.utils.get(guild.roles, name=task.role_name) or await guild.create_role(name=task.role_name)
                await member.add_roles(role)
                task.status = 'done'
            except: task.status = 'error'
        db.session.commit()

@bot.event
async def on_ready():
    if not check_queue.is_running(): check_queue.start()

# --- МАРШРУТЫ ---
@app.route('/')
def index():
    auth_url = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={urllib.parse.quote(REDIRECT_URI)}&response_type=code&scope=identify+guilds.members.read"
    if 'user_id' not in session: return render_template('login.html', auth_url=auth_url)
    user = User.query.filter_by(discord_id=session['user_id']).first()
    cases = Case.query.order_by(Case.date.desc()).all()
    return render_template('index.html', user=user, cases=cases)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    r = requests.post("https://discord.com/api/v10/oauth2/token", data={
        'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 
        'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT_URI
    }).json()
    access_token = r.get('access_token')
    headers = {"Authorization": f"Bearer {access_token}"}
    u_info = requests.get("https://discord.com/api/v10/users/@me", headers=headers).json()
    m_info = requests.get(f"https://discord.com/api/v10/users/@me/guilds/{GUILD_ID}/member", headers=headers).json()
    display_name = m_info.get('nick') or u_info.get('global_name') or u_info.get('username')
    user_role = 'Гражданин'
    if 'roles' in m_info:
        for r_id in m_info['roles']:
            if r_id in ROLE_MAP:
                user_role = ROLE_MAP[r_id]
                break 
    user = User.query.filter_by(discord_id=u_info['id']).first()
    if not user:
        user = User(discord_id=u_info['id'], username=display_name, role=user_role)
        db.session.add(user)
    else: 
        user.username = display_name
        user.role = user_role
    db.session.commit()
    session['user_id'] = u_info['id']
    return redirect('/')

@app.route('/create_case', methods=['POST'])
def create_case():
    if 'user_id' not in session: return redirect('/')
    
    user = User.query.filter_by(discord_id=session['user_id']).first()
    u_name = user.username if user else "Неизвестный заявитель"
    
    ctype = request.form.get('case_type')
    num = f"{ctype}-{Case.query.filter_by(case_type=ctype).count() + 1:03d}"
    
    new_case = Case(
        case_num=num, 
        case_type=ctype, 
        author_id=session['user_id'], 
        title=request.form.get('title'), 
        content=request.form.get('content'), 
        status='Новый'
    )
    
    db.session.add(new_case)
    db.session.add(DiscordQueue(discord_id=session['user_id'], role_name=num))
    db.session.commit()
    
    send_discord_log("🆕 Подан новый иск!", f"**Номер:** {num}\n**Заявитель:** {u_name}\n**Суть:** {new_case.title}", color=0xc5a059)
    
    return redirect('/')

@app.route('/take_case/<int:case_id>')
def take_case(case_id):
    user = User.query.filter_by(discord_id=session.get('user_id')).first()
    if not user or user.role == 'Гражданин': return redirect('/')
    case = Case.query.get(case_id)
    if not case.judge_id:
        case.judge_id = user.username
        case.status = 'В работе'
        db.session.commit()
        send_discord_log("👨‍⚖️ Иск взят в работу", f"**Номер:** {case.case_num}\n**Судья:** {user.username}", color=0x3498db)
    return redirect('/')

@app.route('/answer_case/<int:case_id>', methods=['POST'])
def answer_case(case_id):
    user = User.query.filter_by(discord_id=session.get('user_id')).first()
    case = Case.query.get(case_id)
    if not case or case.judge_id != user.username: return redirect('/')
    case.result = request.form.get('result')
    case.status = 'Завершен'
    db.session.commit()
    send_discord_log("✅ Вынесен вердикт!", f"**Номер:** {case.case_num}\n**Судья:** {user.username}\n**Вердикт:** {case.result}", color=0x27ae60)
    return redirect('/')

@app.route('/delete_case/<int:case_id>')
def delete_case(case_id):
    user = User.query.filter_by(discord_id=session.get('user_id')).first()
    if not user or user.role == 'Гражданин': return redirect('/')
    case = Case.query.get(case_id)
    if case:
        db.session.delete(case)
        db.session.commit()
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

def run_bot(): asyncio.run(bot.start(TOKEN))

if __name__ == '__main__':
    with app.app_context():
        # ВНИМАНИЕ: Оставь эти 2 строки ниже только для первого запуска, чтобы обновить базу!
        # После первого успешного иска УДАЛИ строку db.drop_all()
        db.create_all()
    threading.Thread(target=run_bot, daemon=True).start()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))

