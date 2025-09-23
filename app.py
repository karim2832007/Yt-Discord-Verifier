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
# In-memory activation store
#───────────────────────────────────────────────────────────────────────────────
# code → { created_at, yt_time, role_time, discord_id }
pending_activations = {}

#───────────────────────────────────────────────────────────────────────────────
# Timeouts
#───────────────────────────────────────────────────────────────────────────────
CODE_TTL       = 15 * 60         # 15 minutes to verify YouTube
ACTIVATION_TTL = 24 * 60 * 60    # 24 hours of role validity

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
# Shared holographic CSS
#───────────────────────────────────────────────────────────────────────────────
BASE_STYLE = """
<link rel="icon" href="/static/favicon.ico">
<style>
  *{margin:0;padding:0;box-sizing:border-box;}
  body,html{width:100%;height:100%;background:#0a0a0a;color:#eee;
    font-family:'Segoe UI',sans-serif;overflow:hidden;}
  .hero{position:relative;width:100%;min-height:100vh;display:flex;
    flex-direction:column;align-items:center;justify-content:center;
    background:radial-gradient(circle at center,#111 0%,#000 80%);}
  .hero::before{content:"";position:absolute;top:0;left:0;width:100%;
    height:100%;background:url('/static/holo-grid.png') center/cover;
    opacity:.1;animation:holoShift 20s linear infinite;}
  @keyframes holoShift{from{background-position:0 0;}to{background-position:1000px 1000px;}}
  .box{z-index:1;text-align:center;padding:3rem;}
  .title{font-size:4rem;color:#FFD700;text-shadow:0 0 15px #B8860B;
    animation:fadeInDown 1.5s;}
  @keyframes fadeInDown{from{opacity:0;transform:translateY(-50px);}to{opacity:1;transform:translateY(0);}}
  .subtitle{margin-top:1rem;font-size:1.5rem;color:#ccc;animation:fadeIn 2s;}
  @keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
  .cta{margin-top:2rem;padding:1rem 2rem;border:2px solid #fff;border-radius:8px;
    background:rgba(255,255,255,0.1);color:#fff;font-size:1.25rem;
    transition:transform .3s,box-shadow .3s;animation:fadeInUp 1.5s;}
  .cta:hover{transform:scale(1.05);box-shadow:0 0 20px rgba(255,255,255,0.5);}
  @keyframes fadeInUp{from{opacity:0;transform:translateY(50px);}to{opacity:1;transform:translateY(0);}}
  .msg{font-size:2rem;margin-top:2rem;}
  .msg.success{color:#0f0;}
  .msg.error{color:#f00;}
  input{margin-top:1rem;padding:0.5rem;font-size:1.2rem;width:80%;max-width:400px;}
  #result{margin-top:2rem;font-size:1.5rem;}
</style>
"""

#───────────────────────────────────────────────────────────────────────────────
# Templates
#───────────────────────────────────────────────────────────────────────────────
INDEX_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Gaming Mods</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero">
    <div class="box">
      <div class="title">Gaming Mods Membership</div>
      <div class="subtitle">
        Unlock cheat engines & exclusive features<br>
        with YouTube + Discord integration.
      </div>
      <button class="cta" onclick="location.href='{{ google_url }}'">
        Login with Google
      </button>
    </div>
  </section>
</body></html>
"""

SUCCESS_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Success</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero">
    <div class="box">
      <div class="msg success">✅ Subscriber role granted!</div>
    </div>
  </section>
</body></html>
"""

ERROR_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Error</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero">
    <div class="box">
      <div class="msg error">❌ {{ message }}</div>
    </div>
  </section>
</body></html>
"""

CHECK_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Check Role</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero">
    <div class="box">
      <div class="title">Check Your Subscriber Role</div>
      <div class="subtitle">Enter your Discord ID below</div>
      <input id="discordId" type="text" placeholder="Discord ID" />
      <button class="cta" onclick="checkRole()">Check Role</button>
      <div id="result"></div>
    </div>
  </section>
  <script>
    function checkRole() {
      const id = document.getElementById('discordId').value.trim();
      if (!id) return;
      fetch('/status/' + id)
        .then(r => r.json())
        .then(data => {
          const ok = data.ok && data.role_granted;
          document.getElementById('result').innerHTML =
            ok
              ? '<div class="msg success">You have the subscriber role!</div>'
              : '<div class="msg error">Subscriber role not found.</div>';
        })
        .catch(() => {
          document.getElementById('result').innerHTML =
            '<div class="msg error">Error checking status.</div>';
        });
    }
  </script>
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
    pending_activations[code] = {"created_at": now(), "yt_time": None, "role_time": None, "discord_id": None}
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
    if not entry or is_expired(entry["created_at"], CODE_TTL):
        pending_activations.pop(code, None)
        return render_template_string(ERROR_HTML, message="Session expired."), 400

    token = requests.post(
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
    ).json().get("access_token")

    if not token:
        return render_template_string(ERROR_HTML, message="Google auth failed."), 400

    headers, url, params = {"Authorization": f"Bearer {token}"}, "https://www.googleapis.com/youtube/v3/subscriptions", {"part":"snippet","mine":"true","maxResults":50}
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

@app.route("/discord/login")
def discord_login():
    code = request.args.get("code")
    entry = pending_activations.get(code)
    if not entry or not entry["yt_time"] or is_expired(entry["yt_time"], ACTIVATION_TTL):
        pending_activations.pop(code, None)
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

@app.route("/discord/callback")
def discord_callback():
    code = request.args.get("state")
    entry = pending_activations.get(code)
    if not entry:
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

    bot_headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}
    requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers=bot_headers, json={"access_token": access_token}, timeout=20
    )
    resp = requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}/roles/{DISCORD_ROLE_ID}",
        headers=bot_headers, timeout=20
    )

    if resp.status_code in (201, 204):
        entry["role_time"]  = now()
        entry["discord_id"] = discord_id
        return render_template_string(SUCCESS_HTML)
    else:
        detail = resp.json() if resp.headers.get("Content-Type","").startswith("application/json") else {"error": resp.text}
        return render_template_string(ERROR_HTML, message=f"Role assignment failed: {detail}"), 400

@app.route("/status/<discord_id>")
def status(discord_id):
    # JSON endpoint for game to poll
    for entry in pending_activations.values():
        if entry.get("discord_id") == discord_id:
            granted = bool(entry.get("role_time"))
            return jsonify({"ok": True, "role_granted": granted}), 200
    return jsonify({"ok": False}), 404

@app.route("/check")
def check():
    # HTML form for manual in-browser check
    return render_template_string(CHECK_HTML)

#───────────────────────────────────────────────────────────────────────────────
# Run the app
#───────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))