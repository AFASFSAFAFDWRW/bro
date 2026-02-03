import os
import urllib.parse
import requests
import asyncio
import threading
import discord
from discord.ext import tasks, commands
from flask import Flask, redirect, url_for, session, render_template, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

# --- НАСТРОЙКИ ---
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret_key')

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'court.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

GUILD_ID = int(os.getenv('GUILD_ID', '1468002775471226896'))
CLIENT_ID = '1468026057356480674'
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI')
TOKEN = os.getenv('DISCORD_TOKEN')

JUDGE_ROLES_IDS = ['1468030929120399501', '1468030940973498398', '1468030941040738344', '1468030941615226931', '1468030942231793795']

# --- МОДЕЛИ БАЗЫ ---
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
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class DiscordQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50))
    role_name = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')

# --- ЛОГИКА БОТА (ВНУТРИ САЙТА) ---
intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

@tasks.loop(seconds=10)
async def check_queue():
    with app.app_context():
        tasks_to_do = DiscordQueue.query.filter_by(status='pending').all()
        if not tasks_to_do: return
        
        guild = bot.get_guild(GUILD_ID)
        if not guild: return

        for task in tasks_to_do:
            try:
                member = await guild.fetch_member(int(task.discord_id))
                if member:
                    role = discord.utils.get(guild.roles, name=task.role_name)
                    if not role:
                        role = await guild.create_role(name=task.role_name, reason="Иск")
                    await member.add_roles(role)
                    task.status = 'done'
                    print(f"ВЫДАНО: {task.role_name}")
            except Exception as e:
                print(f"ОШИБКА БОТА: {e}")
                task.status = 'error'
        db.session.commit()

@bot.event
async def on_ready():
    print(f"БОТ {bot.user} ОНЛАЙН!")
    if not check_queue.is_running():
        check_queue.start()

# --- МАРШРУТЫ FLASK ---
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
    })
    access_token = r.json().get('access_token')
    headers = {"Authorization": f"Bearer {access_token}"}
    u_info = requests.get("https://discord.com/api/v10/users/@me", headers=headers).json()
    m_info = requests.get(f"https://discord.com/api/v10/users/@me/guilds/{GUILD_ID}/member", headers=headers).json()
    
    user_role = 'Гражданин'
    if 'roles' in m_info:
        for r_id in m_info['roles']:
            if r_id in JUDGE_ROLES_IDS: user_role = 'Председатель Верховного Суда'

    user = User.query.filter_by(discord_id=u_info['id']).first()
    if not user:
        user = User(discord_id=u_info['id'], username=u_info['username'], role=user_role)
        db.session.add(user)
    else:
        user.role = user_role
    db.session.commit()
    session['user_id'] = u_info['id']
    return redirect(url_for('index'))

@app.route('/create_case', methods=['POST'])
def create_case():
    if 'user_id' not in session: return redirect('/')
    ctype = request.form.get('case_type')
    count = Case.query.filter_by(case_type=ctype).count() + 1
    num = f"{ctype}-{count:03d}"
    
    new_case = Case(case_num=num, case_type=ctype, author_id=session['user_id'], title=request.form.get('title'), content=request.form.get('content'))
    task = DiscordQueue(discord_id=session['user_id'], role_name=num)
    db.session.add(new_case); db.session.add(task); db.session.commit()
    return redirect('/')

# --- ЗАПУСК ---
def run_bot():
    asyncio.run(bot.start(TOKEN))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Запускаем бота в отдельном потоке внутри Flask
    threading.Thread(target=run_bot, daemon=True).start()
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
