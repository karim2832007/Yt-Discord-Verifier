import os
import time
import secrets
import string
import logging

import requests
from dotenv import load_dotenv
from flask import Flask, redirect, request, jsonify, render_template_string

#───────────────────────────────────────────────────────────────────────────────
# Setup & Configuration
#───────────────────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(16))

BASE_URL           = os.getenv("BASE_URL", "").rstrip("/")
YOUTUBE_CHANNEL_ID = os.getenv("YOUTUBE_CHANNEL_ID")

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT      = os.getenv("GOOGLE_REDIRECT")

DISCORD_CLIENT_ID     = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT      = os.getenv("DISCORD_REDIRECT")
DISCORD_GUILD_ID      = os.getenv("DISCORD_GUILD_ID")
DISCORD_ROLE_ID       = os.getenv("DISCORD_ROLE_ID")
DISCORD_BOT_TOKEN     = os.getenv("DISCORD_BOT_TOKEN")

# In-memory activation store:
# code → { created_at, yt_verified, discord_id, role_granted, role_time }
pending_activations = {}

# Time-to-live settings
CODE_TTL       = 15 * 60    # 15 min to complete YouTube step
ACTIVATION_TTL = 15 * 60    # 15 min to use your Discord ID in-game

#───────────────────────────────────────────────────────────────────────────────
# Helpers
#───────────────────────────────────────────────────────────────────────────────
def now() -> int:
    return int(time.time())

def gen_code(n: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))

def is_expired(timestamp: int, ttl: int) -> bool:
    return (now() - timestamp) > ttl

#───────────────────────────────────────────────────────────────────────────────
# Holographic theme + enlarged text
#───────────────────────────────────────────────────────────────────────────────
BASE_STYLE = """
<link rel="icon" href="/static/favicon.ico">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body,html {
    width:100%; height:100%; overflow:hidden;
    background:#0a0a0a; color:#eee;
    font-family:'Segoe UI',sans-serif; font-size:18px;
  }
  .hero {
    position:relative; display:flex; flex-direction:column;
    align-items:center; justify-content:center;
    width:100%; height:100vh;
    background:radial-gradient(circle at center,#111 0%,#000 80%);
  }
  .hero::before {
    content:""; position:absolute; top:0; left:0;
    width:100%; height:100%;
    background:
      linear-gradient(rgba(255,255,255,0.05) 1px,transparent 1px) 0 0,
      linear-gradient(90deg,rgba(255,255,255,0.05) 1px,transparent 1px) 0 0;
    background-size:50px 50px; opacity:0.1;
    animation:shiftGrid 30s linear infinite;
  }
  @keyframes shiftGrid {
    from { background-position:0 0; }
    to   { background-position:1000px 1000px; }
  }
  .box { position:relative; z-index:1; text-align:center; padding:2rem; }
  .title {
    font-size:3.5rem; color:#FFD700;
    text-shadow:0 0 10px #B8860B;
    animation:fadeInDown 1.5s ease-out;
  }
  @keyframes fadeInDown {
    from { opacity:0; transform:translateY(-50px); }
    to   { opacity:1; transform:translateY(0); }
  }
  .subtitle {
    margin-top:1rem; font-size:1.5rem; color:#ccc;
    animation:fadeIn 2s ease-in-out;
  }
  .info {
    margin-top:1.25rem; font-size:1.5rem; color:#fff;
  }
  @keyframes fadeIn { from{opacity:0;} to{opacity:1;} }
  .cta {
    margin-top:2rem; padding:1rem 2rem; font-size:1.25rem;
    font-weight:bold; color:#fff; background:rgba(255,255,255,0.1);
    border:2px solid #fff; border-radius:8px;
    cursor:pointer; transition:.3s;
    animation:fadeInUp 1.5s ease-out;
  }
  .cta:hover {
    transform:scale(1.05);
    box-shadow:0 0 20px rgba(255,255,255,0.5);
  }
  @keyframes fadeInUp {
    from { opacity:0; transform:translateY(50px); }
    to   { opacity:1; transform:translateY(0); }
  }
  .msg { margin-top:2rem; font-size:2rem; }
  .msg.success { color:#0f0; }
  .msg.error   { color:#f00; }
  input[type="text"] {
    margin-top:1rem; padding:.75rem; font-size:1.2rem;
    width:80%; max-width:400px; border-radius:4px; border:none;
  }
  #result { margin-top:1.5rem; font-size:1.5rem; }
</style>
"""

#───────────────────────────────────────────────────────────────────────────────
# Templates
#───────────────────────────────────────────────────────────────────────────────
INDEX_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Gaming Mods</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero"><div class="box">
    <div class="title">Gaming Mods Membership</div>
    <div class="subtitle">
      One-click YouTube login & Discord role grant<br>
      for exclusive mods and tools.
    </div>
    <button class="cta" onclick="location.href='{{ google_url }}'">
      Login with Google
    </button>
  </div></section>
</body></html>
"""

SUCCESS_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Success</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero"><div class="box">
    <div class="msg success">✅ Subscriber role granted!</div>
    <div class="info">
      Your Discord ID: <strong>{{ discord_id }}</strong>
    </div>
    <div class="subtitle">
      Copy this ID into your game within 15 minutes.
    </div>
  </div></section>
</body></html>
"""

ERROR_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Error</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero"><div class="box">
    <div class="msg error">❌ {{ message }}</div>
    <div class="subtitle">
      Please try again or contact support.
    </div>
  </div></section>
</body></html>
"""

#───────────────────────────────────────────────────────────────────────────────
# Routes
#───────────────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template_string(
        INDEX_HTML,
        google_url=f"{BASE_URL}/google/login"
    )

@app.route("/google/login")
def google_login():
    code = gen_code()
    pending_activations[code] = {
        "created_at": now(),
        "yt_verified": False,
        "discord_id": None,
        "role_granted": False,
        "role_time": None
    }
    logging.info(f"New activation code: {code}")
    oauth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT}"
        "&scope=https://www.googleapis.com/auth/youtube.readonly"
        "&response_type=code&access_type=online&prompt=consent"
        f"&state={code}"
    )
    return redirect(oauth_url)

@app.route("/google/callback")
def google_callback():
    code = request.args.get("state")
    entry = pending_activations.get(code)
    if not entry or is_expired(entry["created_at"], CODE_TTL):
        pending_activations.pop(code, None)
        return render_template_string(ERROR_HTML, message="Session expired."), 400

    token_data = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": request.args.get("code"),
            "redirect_uri": GOOGLE_REDIRECT,
            "grant_type": "authorization_code"
        },
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        timeout=10
    ).json()
    token = token_data.get("access_token")
    if not token:
        return render_template_string(ERROR_HTML, message="Google auth failed."), 400

    headers = {"Authorization": f"Bearer {token}"}
    url     = "https://www.googleapis.com/youtube/v3/subscriptions"
    params  = {"part":"snippet","mine":"true","maxResults":50}
    subscribed = False
    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=10).json()
        for item in resp.get("items", []):
            if item.get("snippet", {}).get("resourceId", {}).get("channelId") == YOUTUBE_CHANNEL_ID:
                subscribed = True
                break
        if subscribed or not resp.get("nextPageToken"):
            break
        params["pageToken"] = resp["nextPageToken"]

    if not subscribed:
        return render_template_string(ERROR_HTML, message="YouTube sub not found."), 400

    entry["yt_verified"] = True
    return redirect(f"{BASE_URL}/discord/login?code={code}")

@app.route("/discord/login")
def discord_login():
    code = request.args.get("code")
    entry = pending_activations.get(code)
    if not entry or not entry["yt_verified"] or is_expired(entry["created_at"], CODE_TTL):
        pending_activations.pop(code, None)
        return render_template_string(ERROR_HTML, message="Activation expired."), 400

    oauth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        "&response_type=code"
        "&scope=identify%20guilds.join"
        f"&state={code}"
    )
    return redirect(oauth_url)

@app.route("/discord/callback")
def discord_callback():
    code = request.args.get("state")
    entry = pending_activations.get(code)
    if not entry:
        return render_template_string(ERROR_HTML, message="Session expired."), 400

    token_data = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": request.args.get("code"),
            "redirect_uri": DISCORD_REDIRECT
        },
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        timeout=10
    ).json()
    access = token_data.get("access_token")
    if not access:
        return render_template_string(ERROR_HTML, message="Discord auth failed."), 400

    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access}"},
        timeout=10
    ).json()
    discord_id = user.get("id")
    if not discord_id:
        return render_template_string(ERROR_HTML, message="Failed to fetch user."), 400

    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers=bot_headers,
        json={"access_token": access},
        timeout=10
    )
    role_resp = requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}"
        f"/members/{discord_id}/roles/{DISCORD_ROLE_ID}",
        headers=bot_headers,
        timeout=10
    )

    granted = role_resp.status_code in (201, 204)
    entry["discord_id"]   = discord_id
    entry["role_granted"] = granted
    entry["role_time"]    = now()

    if granted:
        logging.info(f"Role granted to {discord_id}")
        return render_template_string(
            SUCCESS_HTML,
            discord_id=discord_id
        )
    else:
        detail = (role_resp.json()
                  if role_resp.headers.get("Content-Type","").startswith("application/json")
                  else {"error": role_resp.text})
        return render_template_string(ERROR_HTML, message=f"Role failed: {detail}"), 400

@app.route("/status/<discord_id>")
def status(discord_id):
    """
    JSON endpoint for game polling.
    Returns {ok: true, role_granted: bool} if found and within 15 min,
    or {ok: false} / 404 otherwise.
    """
    for entry in pending_activations.values():
        if entry.get("discord_id") == discord_id:
            granted = entry.get("role_granted", False)
            rt = entry.get("role_time", 0)
            if granted and is_expired(rt, ACTIVATION_TTL):
                granted = False
            return jsonify({"ok": True, "role_granted": granted}), 200
    return jsonify({"ok": False}), 404

if __name__ == "__main__":
    logging.info("Starting server…")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))