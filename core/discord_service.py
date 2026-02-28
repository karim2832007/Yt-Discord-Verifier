from core.discord_client import bot, GUILD_ID
import requests

# ---------------------------------------------------------
# BASIC GUILD + MEMBER HELPERS
# ---------------------------------------------------------

def get_guild():
    return bot.get_guild(GUILD_ID)

def get_member(discord_id):
    guild = get_guild()
    if not guild:
        return None
    return guild.get_member(int(discord_id))

def get_user_info(discord_id):
    member = get_member(discord_id)

    if not member:
        return {
            "ok": False,
            "reason": "not_in_server"
        }

    roles = [str(r.id) for r in member.roles if r.name != "@everyone"]

    return {
        "ok": True,
        "discord_id": discord_id,
        "username": member.name,
        "avatar": str(member.avatar.url) if member.avatar else None,
        "roles": roles,
        "is_member": True
    }

# ---------------------------------------------------------
# GET ALL ROLES FROM DISCORD (LIVE)
# ---------------------------------------------------------

def get_all_roles():
    guild = get_guild()
    if not guild:
        return []

    return [
        {
            "id": str(role.id),
            "name": role.name,
            "position": role.position
        }
        for role in guild.roles
        if role.name != "@everyone"
    ]

# ---------------------------------------------------------
# SEND ROLES TO PHP API
# ---------------------------------------------------------

def sync_roles_to_php():
    roles = get_all_roles()

    try:
        response = requests.post(
            "http://127.0.0.1:5000/discord/sync_roles",
            json={"roles": roles},
            timeout=5
        )
        print("[SYNC] Sent roles to PHP:", response.text)
    except Exception as e:
        print("[SYNC] Failed to send roles to PHP:", e)

# ---------------------------------------------------------
# AUTO-SYNC ON BOT STARTUP
# ---------------------------------------------------------

@bot.event
async def on_ready():
    print(f"[BOT] Logged in as {bot.user}")
    sync_roles_to_php()

# ---------------------------------------------------------
# MANUAL SYNC COMMAND
# ---------------------------------------------------------

@bot.command()
async def syncroles(ctx):
    sync_roles_to_php()
    await ctx.send("Roles synced to PHP.")
