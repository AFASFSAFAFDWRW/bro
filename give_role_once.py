import discord
import os
import sys
import asyncio

TOKEN = os.getenv('DISCORD_TOKEN')
GUILD_ID = int(os.getenv('GUILD_ID', '1468002775471226896'))

async def give_role():
    if len(sys.argv) < 3: return
    user_id = int(sys.argv[1])
    role_name = sys.argv[2]

    intents = discord.Intents.all()
    client = discord.Client(intents=intents)

    @client.event
    async def on_ready():
        guild = client.get_guild(GUILD_ID)
        if guild:
            member = await guild.fetch_member(user_id)
            if member:
                role = discord.utils.get(guild.roles, name=role_name)
                if not role:
                    role = await guild.create_role(name=role_name)
                await member.add_roles(role)
                print(f"DONE: {role_name} given to {user_id}")
        await client.close()

    await client.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(give_role())
