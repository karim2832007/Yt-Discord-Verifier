# app.py
#
# Flask app for YouTube → Discord verification,
# holographic “Gaming Mods” UI, manual & scheduled role removal,
# and role check endpoint.

from flask import Flask, redirect, request, session, jsonify, render_template_string, url_for
import os
import time
import secrets
import string
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

# ─── Configuration ────────────────────────────────────────────────────────────
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

# ─── Settings ────────────────────────────────────────────────────────────────
CODE_TTL = 15 * 60  # seconds

def now() -> int:
    return int(time.time())

def gen_code(n: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))

def is_expired(ts: int) -> bool:
    return now() - ts > CODE_TTL

def require_session_fields(*keys) -> bool:
    return all(k in session and session[k] is not None for k in keys)


# ─── Landing Page: Holographic UI ────────────────────────────────────────────
@app.route("/")
def home():
    session.clear()
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Gaming Mods Membership</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">

    <!-- FAVICON -->
    <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}" type="image/x-icon">

    <style>
      * { margin:0; padding:0; box-sizing:border-box; }
      body, html {
        width:100%; height:100%; overflow:hidden;
        background:#0a0a0a; font-family:'Segoe UI',sans-serif; color:#eee;
      }
      .hero {
        position:relative; width:100%; height:100vh;
        display:flex; flex-direction:column; align-items:center; justify-content:center;
        background: radial-gradient(circle at center, #111 0%, #000 80%);
      }
      .hero::before {
        content:""; position:absolute; top:0; left:0; width:100%; height:100%;
        background: url('{{ url_for("static", filename="holo-grid.png") }}') center/cover;
        opacity:.1; animation:holoShift 20s linear infinite;
      }
      @keyframes holoShift { from{background-position:0 0;} to{background-position:1000px 1000px;} }

      .hero-title {
        z-index:1;
        font-size:4rem; font-weight:bold; font-style:italic;
        color:#FFD700;
        text-shadow:
          0 0 10px #B8860B,
          0 0 20px #B8860B,
          0 0 30px #FFD700;
        animation:fadeInDown 1.5s ease-out;
      }
      @keyframes fadeInDown {
        from{opacity:0; transform:translateY(-50px);} to{opacity:1; transform:translateY(0);}
      }

      .hero-subtitle {
        z-index:1;
        margin-top:1rem; font-size:1.25rem; max-width:700px; text-align:center;
        color:#ccc; animation:fadeIn 2s ease-in-out;
      }
      @keyframes fadeIn { from{opacity:0;} to{opacity:1;} }

      .cta-btn {
        z-index:1;
        margin-top:2rem;
        padding:1rem 2rem; font-size:1.2rem; font-weight:bold;
        background: rgba(255,255,255,0.1); /* translucent dark */
        color:#fff; border:2px solid #fff; border-radius:8px;
        cursor:pointer; transition: transform .3s ease, box-shadow .3s ease;
        animation:fadeInUp 1.5s ease-out;
      }
      .cta-btn:hover {
        transform:scale(1.05);
        box-shadow:0 0 15px rgba(255,255,255,0.5);
      }
      @keyframes fadeInUp {
        from{opacity:0; transform:translateY(50px);} to{opacity:1; transform:translateY(0);}
      }
    </style>
</head>
<body>
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
</body>
</html>
    """,
    google_url=f"{BASE_URL}/google/login")


# ─── YouTube → Discord OAuth Flow ────────────────────────────────────────────
@app.route("/google/login")
def google_login():
    code = gen_code()
    session.clear()
    session["code"] = code
    session["created"] = now()
    session["status"] = "pending"

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
    if not require_session_fields("code", "created", "status") or is_expired(session["created"]):
        return "Session expired", 400
    if request.args.get("state") != session["code"]:
        return "Invalid state", 400

    code_param = request.args.get("code")
    if not code_param:
        return "Google auth failed", 400

    token_req = requests.post(
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

    if "access_token" not in token_req:
        return "Google auth failed", 400

    headers = {"Authorization": f"Bearer {token_req['access_token']}"}
    url     = "https://www.googleapis.com/youtube/v3/subscriptions"
    params  = {"part": "snippet", "mine": "true", "maxResults": 50}

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
        return render_template_string(_error_page(), message="YouTube subscription not found.")
    session["status"] = "yt_ok"
    return redirect(f"{BASE_URL}/discord/login")


@app.route("/discord/login")
def discord_login():
    # Generate or preserve an OAuth state code
    code = session.get("code")
    if not code:
        code = gen_code()
    session["code"]    = code
    session["created"] = now()
    session["status"]  = "discord_pending"

    # Build the Discord OAuth URL
    discord_auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        "&response_type=code"
        "&scope=identify%20guilds.join"
        f"&state={code}"
    )

    # Render the same “hero” HTML as your home page, but point the button at discord_auth_url
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Gaming Mods Membership</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">

    <!-- FAVICON -->
    <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}" type="image/x-icon">

    <style>
      * { margin:0; padding:0; box-sizing:border-box; }
      body, html {
        width:100%; height:100%; overflow:hidden;
        background:#0a0a0a; font-family:'Segoe UI',sans-serif; color:#eee;
      }
      .hero {
        position:relative; width:100%; height:100vh;
        display:flex; flex-direction:column; align-items:center; justify-content:center;
        background: radial-gradient(circle at center, #111 0%, #000 80%);
      }
      .hero::before {
        content:""; position:absolute; top:0; left:0; width:100%; height:100%;
        background: url('{{ url_for("static", filename="holo-grid.png") }}') center/cover;
        opacity:.1; animation:holoShift 20s linear infinite;
      }
      @keyframes holoShift { from{background-position:0 0;} to{background-position:1000px 1000px;} }

      .hero-title {
        z-index:1;
        font-size:4rem; font-weight:bold; font-style:italic;
        color:#FFD700;
        text-shadow:
          0 0 10px #B8860B,
          0 0 20px #B8860B,
          0 0 30px #FFD700;
        animation:fadeInDown 1.5s ease-out;
      }
      @keyframes fadeInDown {
        from{opacity:0; transform:translateY(-50px);} to{opacity:1; transform:translateY(0);}
      }

      .hero-subtitle {
        z-index:1;
        margin-top:1rem; font-size:1.25rem; max-width:700px; text-align:center;
        color:#ccc; animation:fadeIn 2s ease-in-out;
      }
      @keyframes fadeIn { from{opacity:0;} to{opacity:1;} }

      .cta-btn {
        z-index:1;
        margin-top:2rem;
        padding:1rem 2rem; font-size:1.2rem; font-weight:bold;
        background: rgba(255,255,255,0.1);
        color:#fff; border:2px solid #fff; border-radius:8px;
        cursor:pointer; transition: transform .3s ease, box-shadow .3s ease;
        animation:fadeInUp 1.5s ease-out;
      }
      .cta-btn:hover {
        transform:scale(1.05);
        box-shadow:0 0 15px rgba(255,255,255,0.5);
      }
      @keyframes fadeInUp {
        from{opacity:0; transform:translateY(50px);} to{opacity:1; transform:translateY(0);}
      }
    </style>
</head>
<body>
  <section class="hero">
    <h1 class="hero-title">Gaming Mods</h1>
    <p class="hero-subtitle">
      Unlock cheat engines, gallery tools, and exclusive mod features<br>
      through Discord integration.
    </p>
    <button class="cta-btn" onclick="window.location='{{ discord_url }}'">
      Login with Discord
    </button>
  </section>
</body>
</html>
    """, discord_url=discord_auth_url)


@app.route("/discord/callback")
def discord_callback():
    if not require_session_fields("code", "created", "status") or is_expired(session["created"]):
        return render_template_string(_error_page(), message="Session expired.")
    if request.args.get("state") != session["code"]:
        return render_template_string(_error_page(), message="Invalid state.")

    code_param = request.args.get("code")
    if not code_param:
        return render_template_string(_error_page(), message="Discord auth failed.")

    token_req = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id":     DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type":    "authorization_code",
            "code":          code_param,
            "redirect_uri":  DISCORD_REDIRECT,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    ).json()

    if "access_token" not in token_req:
        return render_template_string(_error_page(), message="Discord auth failed.")

    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token_req['access_token']}"},
        timeout=20,
    ).json()

    if "id" not in user:
        return render_template_string(_error_page(), message="Failed to fetch Discord user.")

    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type":  "application/json",
    }

    # Join guild & assign role
    join_url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['id']}"
    requests.put(join_url, headers=bot_headers,
                 json={"access_token": token_req["access_token"]}, timeout=20)
    role_url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['id']}/roles/{DISCORD_ROLE_ID}"
    resp = requests.put(role_url, headers=bot_headers, timeout=20)

    if resp.status_code in (204, 201):
        return render_template_string(_success_page(), username=user.get("username", "User"))
    else:
        detail = resp.json() if resp.headers.get("Content-Type","").startswith("application/json") else {"error": resp.text}
        return render_template_string(_error_page(), message=f"Role assignment failed: {detail}")

# ─── Templates for Success & Error Pages ─────────────────────────────────────
def _success_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><title>Success</title>
  <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
  <style>
    body, html { width:100%; height:100%; margin:0; background:#000; color:#0f0; display:flex;
      align-items:center; justify-content:center; font-family:'Segoe UI',sans-serif; }
    .box { text-align:center; }
    .msg { font-size:2rem; text-shadow:0 0 10px #0f0; }
  </style>
</head>
<body>
  <div class="box">
    <p class="msg">✅ Success! Role has been assigned.</p>
    <p>You can close this tab.</p>
  </div>
</body>
</html>
"""

def _error_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><title>Error</title>
  <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
  <style>
    body, html { width:100%; height:100%; margin:0; background:#000; color:#f00; display:flex;
      align-items:center; justify-content:center; font-family:'Segoe UI',sans-serif; }
    .box { text-align:center; }
    .msg { font-size:2rem; text-shadow:0 0 10px #f00; }
  </style>
</head>
<body>
  <div class="box">
    <p class="msg">❌ {{ message }}</p>
    <p>Please try again or contact support.</p>
  </div>
</body>
</html>
"""


# ─── Status & Role Removal Logic ─────────────────────────────────────────────
@app.route("/status")
def status_me():
    if "status" not in session:
        return jsonify({"ok": False}), 404
    return jsonify({
        "ok": True,
        "status": session["status"],
        "code": session.get("code"),
        "expired": is_expired(session.get("created",0))
    }), 200

@app.route("/status/<code>")
def status_code(code):
    if session.get("code") != code:
        return jsonify({"ok": False}), 404
    return jsonify({"ok": True, "status": session["status"]}), 200

def remove_role_daily():
    bot_headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}
    r = requests.get(f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000",
                     headers=bot_headers, timeout=20)
    try:
        members = r.json()
    except:
        print("Parse error:", r.text); return
    if not isinstance(members, list):
        print("Unexpected format:", members); return

    removed = 0
    for m in members:
        if DISCORD_ROLE_ID in m.get("roles", []):
            u = m["user"]["id"]
            rr = requests.delete(f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}"
                                 f"/members/{u}/roles/{DISCORD_ROLE_ID}",
                                 headers=bot_headers, timeout=20)
            if rr.status_code == 204:
                removed += 1
    print(f"[RoleRemoval] Removed {removed} roles.")

@app.route("/remove_roles_now")
def remove_roles_now():
    remove_role_daily()
    return "Role removal triggered.", 200

@app.route("/has_role/<discord_id>")
def has_role(discord_id):
    r = requests.get(f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
                     headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=20)
    if r.status_code != 200:
        return jsonify({"ok": False, "error": "User not found"}), 404
    data = r.json()
    return jsonify({"ok": True, "has_role": DISCORD_ROLE_ID in data.get("roles", [])}), 200


# ─── App Runner ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
