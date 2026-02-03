import os
import urllib.parse
import requests
from flask import Flask, redirect, url_for, session, render_template, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

app = Flask(__name__)
# Секретный ключ для сессий (из настроек Render)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret_key_default')

# Путь к базе данных
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'court.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Данные Discord (Берем из Environment Variables на Render)
GUILD_ID = os.getenv('GUILD_ID', '1468002775471226896')
CLIENT_ID = '1468026057356480674'
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
# На Render адрес будет типа https://your-app-name.onrender.com/callback
REDIRECT_URI = os.getenv('REDIRECT_URI', 'https://sydebnayavlast.pythonanywhere.com/callback')

JUDGE_ROLES_IDS = ['1468030929120399501', '1468030940973498398', '1468030941040738344', '1468030941615226931', '1468030942231793795']

encoded_uri = urllib.parse.quote(REDIRECT_URI, safe='')
AUTH_URL = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={encoded_uri}&response_type=code&scope=identify+guilds.members.read"

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

with app.app_context():
    db.create_all()

def generate_case_number(prefix):
    count = Case.query.filter_by(case_type=prefix).count() + 1
    return f"{prefix}-{count:03d}"

@app.route('/')
def index():
    if 'user_id' not in session: return render_template('login.html', auth_url=AUTH_URL)
    user = User.query.filter_by(discord_id=session['user_id']).first()
    if not user: 
        session.clear()
        return redirect('/')
    cases = Case.query.order_by(Case.date.desc()).all() if user.role != 'Гражданин' else Case.query.filter_by(author_id=user.discord_id).order_by(Case.date.desc()).all()
    return render_template('index.html', user=user, cases=cases)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    r = requests.post("https://discord.com/api/v10/oauth2/token", data={
        'client_id': CLIENT_ID, 
        'client_secret': CLIENT_SECRET, 
        'grant_type': 'authorization_code', 
        'code': code, 
        'redirect_uri': REDIRECT_URI
    })
    token_data = r.json()
    access_token = token_data.get('access_token')
    
    if not access_token: return f"Ошибка Discord: {token_data.get('error_description', 'Неизвестная ошибка')}", 400
    
    headers = {"Authorization": f"Bearer {access_token}"}
    u_info = requests.get("https://discord.com/api/v10/users/@me", headers=headers).json()
    m_info = requests.get(f"https://discord.com/api/v10/users/@me/guilds/{GUILD_ID}/member", headers=headers).json()
    
    user_role = 'Гражданин'
    if 'roles' in m_info:
        for r_id in m_info['roles']:
            if r_id in JUDGE_ROLES_IDS:
                user_role = 'Председатель Верховного Суда'
                break

    user = User.query.filter_by(discord_id=u_info['id']).first()
    if not user:
        user = User(discord_id=u_info['id'], username=u_info['username'], role=user_role)
        db.session.add(user)
    else:
        user.role = user_role
        user.username = u_info['username']
    db.session.commit()
    session['user_id'] = u_info['id']
    return redirect(url_for('index'))

@app.route('/create_case', methods=['POST'])
def create_case():
    if 'user_id' not in session: return redirect('/')
    ctype = request.form.get('case_type')
    num = generate_case_number(ctype)
    new_case = Case(case_num=num, case_type=ctype, author_id=session['user_id'], title=request.form.get('title'), content=request.form.get('content'))
    task = DiscordQueue(discord_id=session['user_id'], role_name=num)
    db.session.add(new_case); db.session.add(task); db.session.commit()
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)