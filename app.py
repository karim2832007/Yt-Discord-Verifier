import os
import time
import secrets
import string
import requests
from dotenv import load_dotenv
from flask import (
    Flask, redirect, request,
    jsonify, render_template_string
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
# In-memory activation store
#───────────────────────────────────────────────────────────────────────────────
# Maps code → { created_at, yt_time, role_time, discord_id }
pending_activations = {}

#───────────────────────────────────────────────────────────────────────────────
# Timeouts
#───────────────────────────────────────────────────────────────────────────────
CODE_TTL       = 15 * 60         # 15 minutes for Google confirmation
ACTIVATION_TTL = 24 * 60 * 60    # 24 hours for role validity

#───────────────────────────────────────────────────────────────────────────────
# Helpers
#───────────────────────────────────────────────────────────────────────────────
def now() -> int:
    return int(time.time())

def gen_code(n: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))

def is_expired(ts: int, ttl: int) -> bool:
    return (now() - ts) > ttl

#───────────────────────────────────────────────────────────────────────────────
# HTML templates (all pages share the same holographic theme)
#───────────────────────────────────────────────────────────────────────────────
BASE_STYLE = """
<link rel="icon" href="/static/favicon.ico">
<style>
  *{margin:0;padding:0;box-sizing:border-box;}
  body,html{width:100%;height:100%;background:#000;color:#eee;
    font-family:'Segoe UI',sans-serif;overflow-x:hidden;}
  .hero{position:relative;width:100%;min-height:100vh;display:flex;
    flex-direction:column;align-items:center;justify-content:center;
    background:radial-gradient(circle at center,#111 0%,#000 80%);}
  .hero::before{content:"";position:absolute;top:0;left:0;width:100%;
    height:100%;background:url('/static/holo-grid.png') center/cover;
    opacity:.1;animation:holoShift 20s linear infinite;}
  @keyframes holoShift{from{background-position:0 0;}to{background-position:1000px 1000px;}}
  .title{z-index:1;font-size:3rem;font-weight:bold;color:#FFD700;
    text-shadow:0 0 10px #B8860B,0 0 20px #FFD700;animation:fadeInDown 1.5s;}
  @keyframes fadeInDown{from{opacity:0;transform:translateY(-50px);}to{opacity:1;transform:translateY(0);}}
  .subtitle{z-index:1;margin-top:1rem;font-size:1.2rem;color:#ccc;animation:fadeIn 2s;}
  @keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
  .cta{z-index:1;margin-top:2rem;padding:1rem 2rem;
    background:rgba(255,255,255,0.1);color:#fff;border:2px solid #fff;
    border-radius:8px;font-size:1.1rem;cursor:pointer;
    transition:transform .3s,box-shadow .3s;animation:fadeInUp 1.5s;}
  .cta:hover{transform:scale(1.05);box-shadow:0 0 15px rgba(255,255,255,0.5);}
  @keyframes fadeInUp{from{opacity:0;transform:translateY(50px);}to{opacity:1;transform:translateY(0);}}
  .box{z-index:1;text-align:center;padding:2rem;}
  .msg{font-size:2rem;color:#0f0;}
  .error{font-size:2rem;color:#f00;}
  .info{margin-top:1rem;color:#0f0;}
  .link{color:#0f0;text-decoration:underline;}
</style>
"""

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Gaming Mods</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero">
    <div class="box">
      <div class="title">Gaming Mods Membership</div>
      <div class="subtitle">
        Unlock cheat engines, gallery tools & exclusive mod features<br>
        via YouTube + Discord integration.
      </div>
      <button class="cta" onclick="location.href='{{ google_url }}'">
        Login with Google
      </button>
    </div>
  </section>
</body></html>
"""

SUCCESS_HTML = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Success</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero">
    <div class="box">
      <div class="msg">✅ Subscriber role granted!</div>
      <div class="info">Discord ID: <strong>{{ user_id }}</strong></div>
      <div class="info">Enter this ID in your game within 1 hour.</div>
      <div class="info">Check status anytime:</div>
      <a class="link" href="{{ base_url }}/status_by_id/{{ user_id }}">
        {{ base_url }}/status_by_id/{{ user_id }}
      </a>
    </div>
  </section>
</body></html>
"""

ERROR_HTML = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Error</title>
""" + BASE_STYLE + """
</head><body>
  <section class="hero">
    <div class="box">
      <div class="error">❌ {{ message }}</div>
      <div class="info">Please try again or contact support.</div>
    </div>
  </section>
</body></html>
"""

#───────────────────────────────────────────────────────────────────────────────
# 1) Landing page
#───────────────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template_string(
        INDEX_HTML,
        google_url=f"{BASE_URL}/google/login"
    )

#───────────────────────────────────────────────────────────────────────────────
# 2) Google login & YouTube check
#───────────────────────────────────────────────────────────────────────────────
@app.route("/google/login")
def google_login():
    code = gen_code()
    pending_activations[code] = {
        "created_at": now(),
        "yt_time": None,
        "role_time": None,
        "discord_id": None
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
        return render_template_string(ERROR_HTML, message="Invalid session.")
    if is_expired(entry["created_at"], CODE_TTL):
        del pending_activations[code]
        return render_template_string(ERROR_HTML, message="Session expired.")

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
        return render_template_string(ERROR_HTML, message="Google auth failed.")

    headers = {"Authorization": f"Bearer {token}"}
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
        return render_template_string(ERROR_HTML, message="YouTube sub not found.")

    entry["yt_time"] = now()
    return redirect(f"{BASE_URL}/discord/login?code={code}")

#───────────────────────────────────────────────────────────────────────────────
# 3) Discord login
#───────────────────────────────────────────────────────────────────────────────
@app.route("/discord/login")
def discord_login():
    code = request.args.get("code")
    entry = pending_activations.get(code)
    if not entry or not entry["yt_time"]:
        return render_template_string(ERROR_HTML, message="Verify YouTube first.")
    if is_expired(entry["yt_time"], ACTIVATION_TTL):
        del pending_activations[code]
        return render_template_string(ERROR_HTML, message="Activation expired.")

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
# 4) Discord callback & role assignment
#───────────────────────────────────────────────────────────────────────────────
@app.route("/discord/callback")
def discord_callback():
    code = request.args.get("state")
    entry = pending_activations.get(code)
    if not entry or not entry["yt_time"]:
        return render_template_string(ERROR_HTML, message="Session expired.")

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
        return render_template_string(ERROR_HTML, message="Discord auth failed.")

    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20
    ).json()
    discord_id = user.get("id")
    if not discord_id:
        return render_template_string(ERROR_HTML, message="Failed to fetch user.")

    # join guild + assign role
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

    if resp.status_code in (201, 204):
        entry["role_time"]   = now()
        entry["discord_id"]  = discord_id
        return render_template_string(
            SUCCESS_HTML,
            user_id=discord_id,
            base_url=BASE_URL
        )
    else:
        detail = resp.json() if resp.headers.get("Content-Type","").startswith("application/json") else {"error": resp.text}
        return render_template_string(ERROR_HTML, message=f"Role assignment failed: {detail}")

#───────────────────────────────────────────────────────────────────────────────
# 5) Status by code (for Ren’Py polling)
#───────────────────────────────────────────────────────────────────────────────
@app.route("/has_role_recent")
def has_role_recent():
    code = request.args.get("code")
    entry = pending_activations.get(code, {})
    valid = bool(entry.get("role_time")) and not is_expired(entry["role_time"], ACTIVATION_TTL)
    return jsonify({"ok": True, "has_role": valid})

@app.route("/status/<code>")
def status_code(code):
    entry = pending_activations.get(code)
    if not entry:
        return jsonify({"ok": False}), 404
    return jsonify({
        "ok": True,
        "yt_verified": bool(entry.get("yt_time")),
        "role_granted": bool(entry.get("role_time")),
        "expired":   is_expired(entry.get("created_at",0), CODE_TTL)
    })

#───────────────────────────────────────────────────────────────────────────────
# 6) Status by Discord ID (browser-friendly)
#───────────────────────────────────────────────────────────────────────────────
@app.route("/status_by_id/<discord_id>")
def status_by_id(discord_id):
    for entry in pending_activations.values():
        if entry.get("discord_id") == discord_id:
            granted = bool(entry.get("role_time"))
            expired = is_expired(entry.get("role_time",0), ACTIVATION_TTL)
            return render_template_string(
                SUCCESS_HTML if granted and not expired else ERROR_HTML,
                user_id=discord_id,
                base_url=BASE_URL,
                message = "Role expired." if granted and expired else "You do not have the subscriber role."
            )
    return render_template_string(ERROR_HTML, message="Discord ID not found."), 404

#───────────────────────────────────────────────────────────────────────────────
# 7) Role cleanup and lookup (JSON)
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
    try:
        members = r.json()
    except:
        return jsonify({"ok": False, "error": "Parse error"}), 500

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

    return jsonify({"ok": True, "removed": removed})

@app.route("/has_role/<discord_id>")
def has_role(discord_id):
    r = requests.get(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=20
    )
    if r.status_code != 200:
        return jsonify({"ok": False, "error": "User not found"}), 404
    data = r.json()
    return jsonify({"ok": True, "has_role": DISCORD_ROLE_ID in data.get("roles", [])})

#───────────────────────────────────────────────────────────────────────────────
# Run the app
#───────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))