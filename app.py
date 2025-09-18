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

# In-memory store
SESSIONS = {}
CODE_TTL = 15 * 60

def now(): return int(time.time())
def gen_code(n=6): return "".join(secrets.choice(string.digits) for _ in range(n))
def cleanup():
    expired = [c for c, s in SESSIONS.items() if now() - s["created"] > CODE_TTL]
    for c in expired: SESSIONS.pop(c, None)

@app.route("/")
def home():
    cleanup()
    code = gen_code()
    SESSIONS[code] = {"created": now(), "status": "pending", "discord_id": None}
    session["code"] = code
    return render_template_string("""
    <h2>YouTube → Discord verification</h2>
    <p>Your code: <b>{{code}}</b></p>
    <a href="{{google_url}}">Login with Google</a>
    """, code=code, google_url=f"{BASE_URL}/google/login?code={code}")

@app.route("/google/login")
def google_login():
    code = request.args.get("code")
    if not code or code not in SESSIONS: return "Invalid session", 400
    session["code"] = code
    return redirect(
        f"https://accounts.google.com/o/oauth2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT}"
        f"&scope=https://www.googleapis.com/auth/youtube.readonly"
        f"&response_type=code&access_type=online&prompt=consent"
        f"&state={code}"
    )

@app.route("/google/callback")
def google_callback():
    code = request.args.get("state")
    if not code or code not in SESSIONS: return "Session expired", 400
    token = requests.post("https://oauth2.googleapis.com/token", data={
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": request.args.get("code"),
        "redirect_uri": GOOGLE_REDIRECT,
        "grant_type": "authorization_code"
    }).json()
    if "access_token" not in token: return "Google auth failed", 400
    headers = {"Authorization": f"Bearer {token['access_token']}"}
    url = "https://www.googleapis.com/youtube/v3/subscriptions"
    params = {"part": "snippet", "mine": "true", "maxResults": 50}
    subscribed = False
    while True:
        resp = requests.get(url, headers=headers, params=params).json()
        for item in resp.get("items", []):
            if item["snippet"]["resourceId"]["channelId"] == YOUTUBE_CHANNEL_ID:
                subscribed = True
                break
        if subscribed or "nextPageToken" not in resp: break
        params["pageToken"] = resp["nextPageToken"]
    if not subscribed:
        SESSIONS[code]["status"] = "failed"
        return "Not subscribed."
    SESSIONS[code]["status"] = "yt_ok"
    return redirect(f"{BASE_URL}/discord/login?code={code}")

@app.route("/discord/login")
def discord_login():
    code = request.args.get("code")
    if not code or code not in SESSIONS or SESSIONS[code]["status"] != "yt_ok":
        return "Verify YouTube first", 400
    return redirect(
        f"https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        f"&response_type=code&scope=identify"
        f"&state={code}"
    )

@app.route("/discord/callback")
def discord_callback():
    code = request.args.get("state")
    if not code or code not in SESSIONS: return "Session expired", 400
    token = requests.post("https://discord.com/api/oauth2/token", data={
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": request.args.get("code"),
        "redirect_uri": DISCORD_REDIRECT
    }, headers={"Content-Type": "application/x-www-form-urlencoded"}).json()
    if "access_token" not in token: return "Discord auth failed", 400
    user = requests.get("https://discord.com/api/users/@me",
                        headers={"Authorization": f"Bearer {token['access_token']}"}).json()
    bot_headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    role_url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['id']}/roles/{DISCORD_ROLE_ID}"
    r = requests.put(role_url, headers=bot_headers)
    if r.status_code in (204, 201):
        SESSIONS[code]["status"] = "done"
        return "Success! Role assigned."
    SESSIONS[code]["status"] = "failed"
    return "Role assignment failed", 400

@app.route("/status/<code>")
def status(code):
    cleanup()
    s = SESSIONS.get(code)
    if not s: return jsonify({"ok": False}), 404
    return jsonify({"ok": True, "status": s["status"], "discord_id": s["discord_id"]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
