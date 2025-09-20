from flask import Flask, redirect, request, session, jsonify, render_template_string
import os, time, secrets, string, requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

# Config
BASE_URL = os.environ["BASE_URL"].rstrip("/")
YOUTUBE_CHANNEL_ID = os.environ["YOUTUBE_CHANNEL_ID"]

GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
GOOGLE_REDIRECT = os.environ["GOOGLE_REDIRECT"]

DISCORD_CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
DISCORD_CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
DISCORD_REDIRECT = os.environ["DISCORD_REDIRECT"]
DISCORD_GUILD_ID = os.environ["DISCORD_GUILD_ID"]
DISCORD_ROLE_ID = os.environ["DISCORD_ROLE_ID"]
DISCORD_BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]

# Settings
CODE_TTL = 15 * 60  # 15 minutes

def now() -> int:
    return int(time.time())

def gen_code(n=6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))

def is_expired(created_ts: int) -> bool:
    return now() - int(created_ts) > CODE_TTL

def require_session_fields(*keys):
    return all(k in session and session[k] is not None for k in keys)

@app.route("/")
def home():
    code = gen_code()
    session.clear()
    session["code"] = code
    session["created"] = now()
    session["status"] = "pending"
    return render_template_string("""
    <h2>YouTube → Discord verification</h2>
    <p>Your code: <b>{{code}}</b></p>
    <p>This code expires in 15 minutes.</p>
    <a href="{{google_url}}">Login with Google</a>
    """, code=code, google_url=f"{BASE_URL}/google/login")

@app.route("/google/login")
def google_login():
    if not require_session_fields("code", "created", "status"):
        return "Invalid session", 400
    if is_expired(session["created"]):
        return "Session expired", 400

    code = session["code"]
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT}"
        f"&scope=https://www.googleapis.com/auth/youtube.readonly"
        f"&response_type=code&access_type=online&prompt=consent"
        f"&state={code}"
    )
    return redirect(auth_url)

@app.route("/google/callback")
def google_callback():
    if not require_session_fields("code", "created", "status"):
        return "Session expired", 400
    if is_expired(session["created"]):
        return "Session expired", 400

    if request.args.get("state") != session["code"]:
        return "Invalid state", 400

    code_param = request.args.get("code")
    if not code_param:
        return "Google auth failed", 400

    token = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code_param,
            "redirect_uri": GOOGLE_REDIRECT,
            "grant_type": "authorization_code",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    ).json()

    if "access_token" not in token:
        return "Google auth failed", 400

    headers = {"Authorization": f"Bearer {token['access_token']}"}
    url = "https://www.googleapis.com/youtube/v3/subscriptions"
    params = {"part": "snippet", "mine": "true", "maxResults": 50}

    subscribed = False
    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=20).json()
        for item in resp.get("items", []):
            res = item.get("snippet", {}).get("resourceId", {})
            if res.get("channelId") == YOUTUBE_CHANNEL_ID:
                subscribed = True
                break
        if subscribed or "nextPageToken" not in resp:
            break
        params["pageToken"] = resp["nextPageToken"]

    if not subscribed:
        session["status"] = "failed"
        return "Not subscribed."

    session["status"] = "yt_ok"
    return redirect(f"{BASE_URL}/discord/login")

@app.route("/discord/login")
def discord_login():
    if not require_session_fields("code", "created", "status"):
        return "Session expired", 400
    if is_expired(session["created"]):
        return "Session expired", 400
    if session["status"] != "yt_ok":
        return "Verify YouTube first", 400

    code = session["code"]
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        f"&response_type=code&scope=identify%20guilds.join"
        f"&state={code}"
    )
    return redirect(auth_url)

@app.route("/discord/callback")
def discord_callback():
    if not require_session_fields("code", "created", "status"):
        return "Session expired", 400
    if is_expired(session["created"]):
        return "Session expired", 400

    if request.args.get("state") != session["code"]:
        return "Invalid state", 400

    code_param = request.args.get("code")
    if not code_param:
        return "Discord auth failed", 400

    token = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code_param,
            "redirect_uri": DISCORD_REDIRECT,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    ).json()

    if "access_token" not in token:
        return "Discord auth failed", 400

    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token['access_token']}"},
        timeout=20,
    ).json()

    if "id" not in user:
        return "Discord user fetch failed", 400

    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
    }

    # Ensure user is in the guild
    add_url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['id']}"
    requests.put(add_url, headers=bot_headers, json={"access_token": token["access_token"]}, timeout=20)

    # Assign the role
    role_url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['id']}/roles/{DISCORD_ROLE_ID}"
    r = requests.put(role_url, headers=bot_headers, timeout=20)

    if r.status_code in (204, 201):
        session["status"] = "done"
        session["discord_id"] = user["id"]
        return render_template_string("<h3>Success! Role assigned.</h3><p>You can close this tab.</p>")
    else:
        session["status"] = "failed"
        try:
            details = r.json()
        except Exception:
            details = {"error": r.text}
        return render_template_string(
            "<h3>Role assignment failed</h3><pre>Status: {{status}} | Body: {{body}}</pre>",
            status=r.status_code, body=details
        ), 400

@app.route("/status")
def status_me():
    if not require_session_fields("status"):
        return jsonify({"ok": False}), 404
    return jsonify({
        "ok": True,
        "status": session.get("status"),
        "discord_id": session.get("discord_id"),
        "code": session.get("code"),
        "created": session.get("created"),
        "expired": is_expired(session["created"]) if "created" in session else None,
    }), 200

@app.route("/status/<code>")
def status_code(code):
    if session.get("code") != code:
        return jsonify({"ok": False}), 404
    return jsonify({
        "ok": True,
        "status": session.get("status"),
        "discord_id": session.get("discord_id"),
    }), 200

from apscheduler.schedulers.background import BackgroundScheduler

def remove_role_daily():
    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
    }
    # Get all members in the guild (max 1000 per request)
    members_url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000"
    members = requests.get(members_url, headers=bot_headers, timeout=20).json()

    removed_count = 0
    for member in members:
        if DISCORD_ROLE_ID in member.get("roles", []):
            user_id = member["user"]["id"]
            role_url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user_id}/roles/{DISCORD_ROLE_ID}"
            r = requests.delete(role_url, headers=bot_headers, timeout=20)
            if r.status_code == 204:
                removed_count += 1

    print(f"[Daily Job] Removed role from {removed_count} members.")

# Schedule the job to run once every 24 hours
scheduler = BackgroundScheduler()
scheduler.add_job(remove_role_daily, "interval", days=1)
scheduler.start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))

@app.route("/has_role/<discord_id>")
def has_role(discord_id):
    bot_headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}"
    r = requests.get(url, headers=bot_headers, timeout=20)

    if r.status_code != 200:
        return jsonify({"ok": False, "error": "User not found"}), 404

    data = r.json()
    has_role = DISCORD_ROLE_ID in data.get("roles", [])
    return jsonify({"ok": True, "has_role": has_role})
