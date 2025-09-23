import os
import time
import secrets
import string
import requests
from dotenv import load_dotenv
from flask import (
    Flask, redirect, request,
    jsonify, render_template_string,
    url_for
)

#───────────────────────────────────────────────────────────────────────────────
# Load environment
#───────────────────────────────────────────────────────────────────────────────
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

#───────────────────────────────────────────────────────────────────────────────
# Configuration
#───────────────────────────────────────────────────────────────────────────────
BASE_URL            = os.environ["BASE_URL"].rstrip("/")
YOUTUBE_CHANNEL_ID  = os.environ["YOUTUBE_CHANNEL_ID"]

GOOGLE_CLIENT_ID     = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
GOOGLE_REDIRECT      = os.environ["GOOGLE_REDIRECT"]

DISCORD_CLIENT_ID     = os.environ["DISCORD_CLIENT_ID"]
DISCORD_CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
DISCORD_REDIRECT      = os.environ["DISCORD_REDIRECT"]
DISCORD_GUILD_ID      = os.environ["DISCORD_GUILD_ID"]
DISCORD_ROLE_ID       = os.environ["DISCORD_ROLE_ID"]
DISCORD_BOT_TOKEN     = os.environ["DISCORD_BOT_TOKEN"]

#───────────────────────────────────────────────────────────────────────────────
# One‐time activation storage
#───────────────────────────────────────────────────────────────────────────────
# Maps code → { created_at, yt_time, role_time }
pending_activations = {}

#───────────────────────────────────────────────────────────────────────────────
# Timeouts
#───────────────────────────────────────────────────────────────────────────────
CODE_TTL       = 15 * 60         # Google code valid for 15 minutes
ACTIVATION_TTL = 24 * 60 * 60    # Role validity for 24 hours

#───────────────────────────────────────────────────────────────────────────────
# Helpers
#───────────────────────────────────────────────────────────────────────────────
def now() -> int:
    return int(time.time())

def gen_code(n: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))

def is_expired(ts: int, ttl: int) -> bool:
    return now() - ts > ttl

#───────────────────────────────────────────────────────────────────────────────
# HTML Templates
#───────────────────────────────────────────────────────────────────────────────
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Gaming Mods Membership</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
<style> /* Holographic UI styles */ 
  *{margin:0;padding:0;box-sizing:border-box;}
  body,html{width:100%;height:100%;overflow:hidden;background:#0a0a0a;
    font-family:'Segoe UI',sans-serif;color:#eee;}
  .hero{position:relative;width:100%;height:100vh;display:flex;
    flex-direction:column;align-items:center;justify-content:center;
    background:radial-gradient(circle at center,#111 0%,#000 80%);}
  .hero::before{content:"";position:absolute;top:0;left:0;width:100%;
    height:100%;background:url('{{ url_for("static","holo-grid.png") }}')center/cover;
    opacity:.1;animation:holoShift 20s linear infinite;}
  @keyframes holoShift{from{background-position:0 0;}to{background-position:1000px 1000px;}}
  .hero-title{z-index:1;font-size:4rem;font-weight:bold;font-style:italic;
    color:#FFD700;text-shadow:0 0 10px #B8860B,0 0 20px #B8860B,0 0 30px #FFD700;
    animation:fadeInDown 1.5s ease-out;}
  @keyframes fadeInDown{from{opacity:0;transform:translateY(-50px);}
    to{opacity:1;transform:translateY(0);}}
  .hero-subtitle{z-index:1;margin-top:1rem;font-size:1.25rem;
    max-width:700px;text-align:center;color:#ccc;
    animation:fadeIn 2s ease-in-out;}
  @keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
  .cta-btn{z-index:1;margin-top:2rem;padding:1rem 2rem;
    font-size:1.2rem;font-weight:bold;background:rgba(255,255,255,0.1);
    color:#fff;border:2px solid #fff;border-radius:8px;cursor:pointer;
    transition:transform .3s ease,box-shadow .3s ease;
    animation:fadeInUp 1.5s ease-out;}
  .cta-btn:hover{transform:scale(1.05);box-shadow:0 0 15px rgba(255,255,255,0.5);}
  @keyframes fadeInUp{from{opacity:0;transform:translateY(50px);}
    to{opacity:1;transform:translateY(0);}}
</style>
</head><body>
  <section class="hero">
    <h1 class="hero-title">Gaming Mods</h1>
    <p class="hero-subtitle">
      Unlock cheat engines, gallery tools, and exclusive mod features<br>
      through YouTube + Discord integration.
    </p>
    <button class="cta-btn" onclick="window.location='{{ google_url }}'">
      Login with Google
    </button>
  </section>
</body></html>
"""

SUCCESS_HTML = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Success</title>
<link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
<style>
  body,html{width:100%;height:100%;margin:0;background:#000;color:#0f0;
    display:flex;align-items:center;justify-content:center;
    font-family:'Segoe UI',sans-serif;}
  .box{text-align:center;}
  .msg{font-size:2rem;text-shadow:0 0 10px #0f0;}
  .info{margin-top:1rem;font-size:1rem;color:#0f0;}
  .link{color:#0f0;text-decoration:underline;}
</style>
</head><body>
  <div class="box">
    <p class="msg">✅ Success! You have the subscriber role.</p>
    <p class="info">Your Discord ID is: <strong>{{ user_id }}</strong></p>
    <p class="info">Copy this ID into the game within the next hour.</p>
    <p class="info">To check your subscription status later, visit:</p>
    <p><a class="link" href="{{ bot_link }}/status/{{ user_id }}">{{ bot_link }}/status/{{ user_id }}</a></p>
    <p class="info">(Link valid for 1 hour from now.)</p>
  </div>
</body></html>
"""

ERROR_HTML = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Error</title>
<link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
<style>
  body,html{width:100%;height:100%;margin:0;background:#000;color:#f00;
    display:flex;align-items:center;justify-content:center;
    font-family:'Segoe UI',sans-serif;}
  .box{text-align:center;}
  .msg{font-size:2rem;text-shadow:0 0 10px #f00;}
</style>
</head><body>
  <div class="box">
    <p class="msg">❌ {{ message }}</p>
    <p>Please try again or contact support.</p>
  </div>
</body></html>
"""

#───────────────────────────────────────────────────────────────────────────────
# 1) Root landing page
#───────────────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template_string(
        INDEX_HTML,
        google_url=f"{BASE_URL}/google/login"
    )

#───────────────────────────────────────────────────────────────────────────────
# 2) Google → YouTube subscription check
#───────────────────────────────────────────────────────────────────────────────
@app.route("/google/login")
def google_login():
    code = gen_code()
    pending_activations[code] = {
        "created_at": now(),
        "yt_time": None,
        "role_time": None
    }
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT}"
        "&scope=https://www.googleapis.com/auth/youtube.readonly"
        "&response_type=code&access_type=online&prompt=consent"
        f"&state={code}"
    )
    return redirect(auth_url)

@app.route("/google/callback")
def google_callback():
    code = request.args.get("state")
    entry = pending_activations.get(code)
    if not entry:
        return render_template_string(ERROR_HTML, message="Invalid session."), 400
    if is_expired(entry["created_at"], CODE_TTL):
        del pending_activations[code]
        return render_template_string(ERROR_HTML, message="Session expired."), 400

    token_resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": request.args.get("code"),
            "redirect_uri": GOOGLE_REDIRECT,
            "grant_type": "authorization_code"
        },
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        timeout=20
    ).json()
    access_token = token_resp.get("access_token")
    if not access_token:
        return render_template_string(ERROR_HTML, message="Google auth failed."), 400

    headers = {"Authorization": f"Bearer {access_token}"}
    url     = "https://www.googleapis.com/youtube/v3/subscriptions"
    params  = {"part":"snippet","mine":"true","maxResults":50}
    subscribed = False

    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=20).json()
        for item in resp.get("items", []):
            if item.get("snippet", {}).get("resourceId", {}).get("channelId") == YOUTUBE_CHANNEL_ID:
                subscribed = True
                break
        if subscribed or "nextPageToken" not in resp:
            break
        params["pageToken"] = resp["nextPageToken"]

    if not subscribed:
        return render_template_string(ERROR_HTML, message="YouTube subscription not found."), 400

    entry["yt_time"] = now()
    return redirect(f"{BASE_URL}/discord/login?code={code}")

#───────────────────────────────────────────────────────────────────────────────
# 3) Discord OAuth login
#───────────────────────────────────────────────────────────────────────────────
@app.route("/discord/login")
def discord_login():
    code = request.args.get("code")
    entry = pending_activations.get(code)
    if not entry or not entry["yt_time"]:
        return render_template_string(ERROR_HTML, message="You must verify YouTube first."), 400
    if is_expired(entry["yt_time"], ACTIVATION_TTL):
        del pending_activations[code]
        return render_template_string(ERROR_HTML, message="Activation expired."), 400

    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        "&response_type=code"
        "&scope=identify%20guilds.join"
        f"&state={code}"
    )
    return redirect(auth_url)

#───────────────────────────────────────────────────────────────────────────────
# 4) Discord OAuth callback & role assignment
#───────────────────────────────────────────────────────────────────────────────
@app.route("/discord/callback")
def discord_callback():
    code = request.args.get("state")
    entry = pending_activations.get(code)
    if not entry or not entry["yt_time"]:
        return render_template_string(ERROR_HTML, message="Session expired."), 400

    token_req = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": request.args.get("code"),
            "redirect_uri": DISCORD_REDIRECT
        },
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        timeout=20
    ).json()
    access_token = token_req.get("access_token")
    if not access_token:
        return render_template_string(ERROR_HTML, message="Discord auth failed."), 400

    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20
    ).json()
    discord_id = user.get("id")
    if not discord_id:
        return render_template_string(ERROR_HTML, message="Failed to fetch Discord user."), 400

    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers=bot_headers,
        json={"access_token": access_token},
        timeout=20
    )
    resp = requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}/roles/{DISCORD_ROLE_ID}",
        headers=bot_headers,
        timeout=20
    )

    if resp.status_code in (204, 201):
        entry["role_time"] = now()
        return render_template_string(
            SUCCESS_HTML,
            user_id=discord_id,
            bot_link=BASE_URL
        )
    else:
        detail = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {"error": resp.text}
        return render_template_string(ERROR_HTML, message=f"Role assignment failed: {detail}")

#───────────────────────────────────────────────────────────────────────────────
# 5) Ren’Py polling & misc endpoints
#───────────────────────────────────────────────────────────────────────────────
@app.route("/has_role_recent")
def has_role_recent():
    code = request.args.get("code")
    entry = pending_activations.get(code, {})
    has_role = bool(entry.get("role_time")) and not is_expired(entry["role_time"], ACTIVATION_TTL)
    return jsonify({"ok": True, "has_role": has_role}), 200

@app.route("/status")
def status_me():
    return jsonify({"ok": False}), 404  # not used

@app.route("/status/<code>")
def status_code(code):
    entry = pending_activations.get(code)
    if not entry:
        return jsonify({"ok": False}), 404
    return jsonify({
        "ok": True,
        "yt_verified": bool(entry.get("yt_time")),
        "role_granted": bool(entry.get("role_time")),
        "expired": is_expired(entry.get("created_at", 0), CODE_TTL)
    }), 200

@app.route("/remove_roles_now")
def remove_roles_now():
    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    r = requests.get(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000",
        headers=bot_headers, timeout=20
    )
    try:
        members = r.json()
    except:
        return "Parse error", 500

    removed = 0
    for m in members:
        if DISCORD_ROLE_ID in m.get("roles", []):
            u = m["user"]["id"]
            rr = requests.delete(
                f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}"
                f"/members/{u}/roles/{DISCORD_ROLE_ID}",
                headers=bot_headers, timeout=20
            )
            if rr.status_code == 204:
                removed += 1

    return f"Removed {removed} roles.", 200

@app.route("/has_role/<discord_id>")
def has_role(discord_id):
    r = requests.get(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=20
    )
    if r.status_code != 200:
        return jsonify({"ok": False, "error": "User not found"}), 404
    data = r.json()
    return jsonify({"ok": True, "has_role": DISCORD_ROLE_ID in data.get("roles", [])}), 200

#───────────────────────────────────────────────────────────────────────────────
# Run the app
#───────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Start Flask on the PORT render provides (default 5000)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))