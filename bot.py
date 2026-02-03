import discord
from discord.ext import tasks, commands
import sqlite3
import os
import asyncio

# --- НАСТРОЙКИ ---
TOKEN = os.getenv('DISCORD_TOKEN')
GUILD_ID = int(os.getenv('GUILD_ID', '1468002775471226896'))

basedir = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(basedir, 'court.db')

intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

@tasks.loop(seconds=5)
async def check_db():
    try:
        guild = bot.get_guild(GUILD_ID)
        if not guild: return

        # Используем контекстный менеджер для SQLite
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, discord_id, role_name FROM discord_queue WHERE status='pending'")
            db_tasks = cursor.fetchall()

            for t_id, d_id, r_name in db_tasks:
                try:
                    # fetch_member если get_member не нашел (юзер не в кэше)
                    member = await guild.fetch_member(int(d_id))
                    if member:
                        role = discord.utils.get(guild.roles, name=r_name)
                        if not role:
                            role = await guild.create_role(name=r_name, reason="Иск создан")
                        
                        await member.add_roles(role)
                        print(f"Роль {r_name} успешно выдана {member.name}")
                    
                    cursor.execute("UPDATE discord_queue SET status='done' WHERE id=?", (t_id,))
                except Exception as e:
                    print(f"Ошибка с юзером {d_id}: {e}")
                    cursor.execute("UPDATE discord_queue SET status='error' WHERE id=?", (t_id,))
            conn.commit()
    except Exception as e:
        print(f"Ошибка цикла базы: {e}")

@bot.event
async def on_ready():
    print(f"--- Бот {bot.user} запущен на Render! ---")
    if not check_db.is_running():
        check_db.start()

if TOKEN:
    bot.run(TOKEN)
else:
    print("Ошибка: DISCORD_TOKEN не найден!")