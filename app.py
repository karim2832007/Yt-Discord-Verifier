import os
import time
import secrets
import string
import requests
from dotenv import load_dotenv
from flask import Flask, redirect, request, jsonify, render_template_string

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
# In-memory stores
#───────────────────────────────────────────────────────────────────────────────
# Pending YouTube verifications (code → timestamp)
pending_activations = {}

# Final user statuses (discord_id → did_grant_role)
user_status = {}

#───────────────────────────────────────────────────────────────────────────────
# Helpers
#───────────────────────────────────────────────────────────────────────────────
def now() -> int:
    return int(time.time())

def gen_code(n: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))

#───────────────────────────────────────────────────────────────────────────────
# Shared HTML theme
#───────────────────────────────────────────────────────────────────────────────
BASE_STYLE = """
<link rel="icon" href="/static/favicon.ico">
<style>
  *{margin:0;padding:0;box-sizing:border-box;}
  body,html{width:100%;height:100%;background:#000;color:#eee;
    font-family:'Segoe UI',sans-serif;overflow:hidden;}
  .hero{position:relative;width:100%;min-height:100vh;display:flex;
    flex-direction:column;align-items:center;justify-content:center;
    background:radial-gradient(circle at center,#111 0%,#000 80%);}
  .hero::before{content:"";position:absolute;top:0;left:0;width:100%;
    height:100%;background:url('/static/holo-grid.png') center/cover;
    opacity:.1;animation:holoShift 20s linear infinite;}
  @keyframes holoShift{from{background-position:0 0;}to{background-position:1000px 1000px;}}
  .box{z-index:1;text-align:center;padding:2rem;}
  .title{font-size:3rem;color:#FFD700;text-shadow:0 0 10px #B8860B;
    animation:fadeInDown 1.5s;}
  @keyframes fadeInDown{from{opacity:0;transform:translateY(-50px);}to{opacity:1;transform:translateY(0);}}
  .subtitle{margin-top:1rem;font-size:1.2rem;color:#ccc;animation:fadeIn 2s;}
  @keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
  .cta{margin-top:2rem;padding:1rem 2rem;border:2px solid #fff;border-radius:8px;
    background:rgba(255,255,255,0.1);color:#fff;cursor:pointer;
    transition:transform .3s,box-shadow .3s;animation:fadeInUp 1.5s;}
  .cta:hover{transform:scale(1.05);box-shadow:0 0 15px rgba(255,255,255,0.5);}
  @keyframes fadeInUp{from{opacity:0;transform:translateY(50px);}to{opacity:1;transform:translateY(0);}}
  .msg{font-size:2rem;margin-bottom:1rem;}
  .msg.success{color:#0f0;}
  .msg.error{color:#f00;}
  .info{margin-top:1rem;color:#0f0;}
  .link{color:#0f0;text-decoration:underline;}
</style>
"""

#───────────────────────────────────────────────────────────────────────────────
# Page templates
#───────────────────────────────────────────────────────────────────────────────
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Gaming Mods</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero">
    <div class="box">
      <div class="title">Gaming Mods Membership</div>
      <div class="subtitle">
        Get your YouTube Subscriber role on Discord<br>
        with one seamless login.
      </div>
      <button class="cta" onclick="location.href='{{ login_url }}'">
        Login & Get Role
      </button>
    </div>
  </section>
</body></html>
"""

RESULT_HTML = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Result</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero">
    <div class="box">
      {% if role_granted %}
        <div class="msg success">✅ Subscriber role granted!</div>
      {% else %}
        <div class="msg error">❌ Could not grant subscriber role.</div>
      {% endif %}
      <div class="info">Your Discord ID: <strong>{{ user_id }}</strong></div>
      {% if role_granted %}
        <div class="info">Copy this ID into your game.</div>
      {% endif %}
    </div>
  </section>
</body></html>
"""

#───────────────────────────────────────────────────────────────────────────────
# 1) Home & “main link”
#───────────────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template_string(
        INDEX_HTML,
        login_url=f"{BASE_URL}/login"
    )

#───────────────────────────────────────────────────────────────────────────────
# 2) Begin Google OAuth → YouTube check
#───────────────────────────────────────────────────────────────────────────────
@app.route("/login")
def login():
    code = gen_code()
    pending_activations[code] = now()
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
    if code not in pending_activations:
        return render_template_string(RESULT_HTML, role_granted=False, user_id="—")
    # Exchange code for token
    token_data = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": Google_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": request.args.get("code"),
            "redirect_uri": GOOGLE_REDIRECT,
            "grant_type": "authorization_code"
        },
        timeout=20
    ).json()
    access_token = token_data.get("access_token")
    if not access_token:
        return render_template_string(RESULT_HTML, role_granted=False, user_id="—")

    # Check YouTube subscription
    headers = {"Authorization": f"Bearer {access_token}"}
    url     = "https://www.googleapis.com/youtube/v3/subscriptions"
    params  = {"part":"snippet","mine":"true","maxResults":50}
    subscribed = False

    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=20).json()
        for item in resp.get("items", []):
            if item.get("snippet", {})\
                   .get("resourceId", {})\
                   .get("channelId") == YOUTUBE_CHANNEL_ID:
                subscribed = True
                break
        if subscribed or "nextPageToken" not in resp:
            break
        params["pageToken"] = resp["nextPageToken"]

    if not subscribed:
        return render_template_string(RESULT_HTML, role_granted=False, user_id="—")

    # Pass through to Discord OAuth
    return redirect(f"{BASE_URL}/discord/login?code={code}")

#───────────────────────────────────────────────────────────────────────────────
# 3) Discord OAuth → Role assignment
#───────────────────────────────────────────────────────────────────────────────
@app.route("/discord/login")
def discord_login():
    code = request.args.get("code")
    if code not in pending_activations:
        return render_template_string(RESULT_HTML, role_granted=False, user_id="—")
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        "&response_type=code"
        "&scope=identify%20guilds.join"
        f"&state={code}"
    )
    return redirect(auth_url)

@app.route("/discord/callback")
def discord_callback():
    code = request.args.get("state")
    if code not in pending_activations:
        return render_template_string(RESULT_HTML, role_granted=False, user_id="—")

    # Exchange Discord code for token
    token_req = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": request.args.get("code"),
            "redirect_uri": DISCORD_REDIRECT
        },
        timeout=20
    ).json()
    access_token = token_req.get("access_token")
    if not access_token:
        return render_template_string(RESULT_HTML, role_granted=False, user_id="—")

    # Fetch Discord ID
    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20
    ).json()
    discord_id = user.get("id", "—")

    # Assign the role in the guild
    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    # Ensure member is in guild
    requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers=bot_headers,
        json={"access_token": access_token},
        timeout=20
    )
    # Give them the subscriber role
    role_resp = requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}"
        f"/roles/{DISCORD_ROLE_ID}",
        headers=bot_headers,
        timeout=20
    )

    # Record final status and render result page
    granted = role_resp.status_code in (201, 204)
    user_status[discord_id] = granted
    return render_template_string(
        RESULT_HTML,
        role_granted=granted,
        user_id=discord_id
    )

#───────────────────────────────────────────────────────────────────────────────
# 4) Status check by Discord ID (JSON for game polling)
#───────────────────────────────────────────────────────────────────────────────
@app.route("/status/<discord_id>")
def status(discord_id):
    if discord_id not in user_status:
        return jsonify({"ok": False}), 404
    return jsonify({
        "ok": True,
        "role_granted": user_status[discord_id]
    }), 200

#───────────────────────────────────────────────────────────────────────────────
# 5) Optional Role Cleanup Endpoint
#───────────────────────────────────────────────────────────────────────────────
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
    members = r.json() if r.status_code == 200 else []
    removed = 0
    for m in members:
        if DISCORD_ROLE_ID in m.get("roles", []):
            rr = requests.delete(
                f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}"
                f"/members/{m['user']['id']}/roles/{DISCORD_ROLE_ID}",
                headers=bot_headers, timeout=20
            )
            if rr.status_code == 204:
                removed += 1
    return jsonify({"ok": True, "removed": removed})

#───────────────────────────────────────────────────────────────────────────────
# Run the app
#───────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))