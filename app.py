import os
import time
import secrets
import string
import logging
import requests
from dotenv import load_dotenv
from flask import Flask, redirect, request, jsonify, render_template_string, session

# ─────────────────────────────────────────────
# Setup & configuration
# ─────────────────────────────────────────────
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(16))

# Allow session cookies to be sent between verifier.gaming-mods.com and gaming-mods.com
app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True
)

BASE_URL = os.getenv("BASE_URL", "").rstrip("/")
YOUTUBE_CHANNEL_ID = os.getenv("YOUTUBE_CHANNEL_ID")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT = os.getenv("GOOGLE_REDIRECT")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
# Verifier flow (YouTube → Discord join + role) callback
DISCORD_REDIRECT = os.getenv("DISCORD_REDIRECT")
# Simple site login (identify-only) callback; defaults to BASE_URL/login/discord/callback
DISCORD_REDIRECT_SIMPLE = os.getenv("DISCORD_REDIRECT_SIMPLE") or (BASE_URL + "/login/discord/callback")

DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID")
DISCORD_ROLE_ID = os.getenv("DISCORD_ROLE_ID")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

# In-memory activation store: code → { created_at, yt_verified, discord_id, role_granted, role_time }
pending_activations = {}

# Global override flag
global_override = False

# In-memory admin overrides { discord_id: bool }
admin_overrides = {}

# Time-to-live settings
CODE_TTL = 15 * 60       # 15 min to complete YouTube step
ACTIVATION_TTL = 15 * 60 # 15 min to use Discord ID in-game

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def now() -> int:
    return int(time.time())

def gen_code(n: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))

def is_expired(timestamp: int, ttl: int) -> bool:
    return (now() - timestamp) > ttl

# ─────────────────────────────────────────────
# Styles & templates
# ─────────────────────────────────────────────
BASE_STYLE = """
<link rel="icon" href="/static/favicon.ico">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body,html {
  width:100%; height:100%; overflow:hidden;
  background:#0a0a0a; color:#eee;
  font-family:'Segoe UI', sans-serif; font-size:18px;
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
    linear-gradient(rgba(255,255,255,0.05) 1px, transparent 1px) 0 0,
    linear-gradient(90deg, rgba(255,255,255,0.05) 1px, transparent 1px) 0 0;
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
  display:inline-block;
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
</style>
"""

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
<a href="/login/discord" class="cta">Login with Discord</a>
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

PORTAL_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Portal</title>
""" + BASE_STYLE + """
</head><body>
<section class="hero"><div class="box">
<div class="title">Gaming Mods Portal</div>
{% if user %}
  <div class="info">Logged in as: <strong>{{ user['username'] }}#{{ user.get('discriminator','') }}</strong></div>
  <div class="subtitle">Discord ID: {{ user['id'] }}</div>
  <a href="/logout" class="cta">Logout</a>
{% else %}
  <div class="subtitle">Login to access your membership and tools.</div>
  <a href="/login/discord" class="cta">Login with Discord</a>
{% endif %}
</div></section>
</body></html>
"""

# ─────────────────────────────────────────────
# Routes — landing
# ─────────────────────────────────────────────
@app.route("/")
def home():
    return render_template_string(INDEX_HTML, google_url=f"{BASE_URL}/google/login")

# ─────────────────────────────────────────────
# Google OAuth → YouTube subscription verify
# ─────────────────────────────────────────────
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
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10
    ).json()
    token = token_data.get("access_token")
    if not token:
        return render_template_string(ERROR_HTML, message="Google auth failed."), 400

    headers = {"Authorization": f"Bearer {token}"}
    url = "https://www.googleapis.com/youtube/v3/subscriptions"
    params = {"part": "snippet", "mine": "true", "maxResults": 50}
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
        return render_template_string(ERROR_HTML, message="YouTube subscription not found."), 400

    entry["yt_verified"] = True
    return redirect(f"{BASE_URL}/discord/login?code={code}")

# ─────────────────────────────────────────────
# Discord OAuth (Verifier flow): join guild + assign role
# ─────────────────────────────────────────────
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
        headers={"Content-Type": "application/x-www-form-urlencoded"},
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
        return render_template_string(ERROR_HTML, message="Failed to fetch Discord user."), 400

    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    # Ensure member exists in guild (join)
    requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers=bot_headers,
        json={"access_token": access},
        timeout=10
    )
    # Assign role
    role_resp = requests.put(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}/roles/{DISCORD_ROLE_ID}",
        headers=bot_headers,
        timeout=10
    )
    granted = role_resp.status_code in (201, 204)
    entry["discord_id"] = discord_id
    entry["role_granted"] = granted
    entry["role_time"] = now()

    if granted:
        logging.info(f"Role granted to {discord_id}")
        return render_template_string(SUCCESS_HTML, discord_id=discord_id)
    else:
        detail = (role_resp.json()
                  if role_resp.headers.get("Content-Type", "").startswith("application/json")
                  else {"error": role_resp.text})
        return render_template_string(ERROR_HTML, message=f"Role failed: {detail}"), 400


# ─────────────────────────────────────────────
# Discord OAuth (Site login): identify-only + session
# ─────────────────────────────────────────────
@app.route("/login/discord")
def discord_login_simple():
    oauth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_SIMPLE}"
        "&response_type=code"
        "&scope=identify"
    )
    return redirect(oauth_url)


@app.route("/login/discord/callback")
def discord_callback_simple():
    code = request.args.get("code")
    if not code:
        return render_template_string(ERROR_HTML, message="Missing code."), 400

    token_data = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DISCORD_REDIRECT_SIMPLE,
            "scope": "identify"
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10
    ).json()
    access = token_data.get("access_token")
    if not access:
        return render_template_string(ERROR_HTML, message="Discord login failed."), 400

    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access}"},
        timeout=10
    ).json()
    if not user.get("id"):
        return render_template_string(ERROR_HTML, message="Failed to fetch Discord user."), 400

    # Save user in session
    session["discord_user"] = {
        "id": user.get("id"),
        "username": user.get("username"),
        "discriminator": user.get("discriminator", "")
    }

    discord_id = user.get("id")

    # Return a modal popup page
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Confirm Your ID</title>
      <style>
        body {{
          background:#0a0a0a; color:#eee; font-family:sans-serif;
          display:flex; align-items:center; justify-content:center;
          height:100vh; margin:0;
        }}
        .modal {{
          background:#111; padding:2rem; border-radius:10px;
          box-shadow:0 0 20px rgba(255,255,255,0.2); text-align:center;
        }}
        .id-box {{
          font-size:1.2rem; margin:1rem 0; color:#FFD700;
        }}
        button {{
          margin:0.5rem; padding:0.75rem 1.5rem; font-size:1rem;
          border:none; border-radius:6px; cursor:pointer;
        }}
        #copyBtn {{ background:#444; color:#fff; }}
        #continueBtn {{ background:#FFD700; color:#000; }}
        #continueBtn:disabled {{ background:#555; color:#999; cursor:not-allowed; }}
      </style>
    </head>
    <body>
      <div class="modal">
        <h2>✅ Logged in successfully!</h2>
        <p>Please copy your Discord ID before continuing:</p>
        <div class="id-box" id="discordId">{discord_id}</div>
        <button id="copyBtn">Copy ID</button>
        <button id="continueBtn" disabled>Continue</button>
      </div>
      <script>
        const copyBtn = document.getElementById("copyBtn");
        const continueBtn = document.getElementById("continueBtn");
        const discordId = document.getElementById("discordId").innerText;

        copyBtn.addEventListener("click", () => {{
          navigator.clipboard.writeText(discordId).then(() => {{
            alert("Discord ID copied to clipboard!");
            continueBtn.disabled = false;
          }});
        }});

        continueBtn.addEventListener("click", () => {{
          window.location.href = "https://gaming-mods.com/index.html";
        }});
      </script>
    </body>
    </html>
    """


# ─────────────────────────────────────────────
# Portal & session routes
# ─────────────────────────────────────────────
@app.route("/portal")
def portal():
    return render_template_string(PORTAL_HTML, user=session.get("discord_user"))


@app.route("/portal/me")
def portal_me():
    user = session.get("discord_user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({
        "ok": True,
        "id": user["id"],
        "username": user["username"],
        "discriminator": user.get("discriminator", "")
    })


@app.route("/logout")
def logout():
    session.pop("discord_user", None)
    return redirect("https://gaming-mods.com/index.html")

# ─────────────────────────────────────────────
# Ren'Py client status check
# ─────────────────────────────────────────────
@app.route("/status/<discord_id>")
def status(discord_id):
    global global_override

    # Global override wins
    if global_override:
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "⚡ Global admin override active"
        }), 200

    # Per-user override
    if admin_overrides.get(discord_id):
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "⚡ Admin override active"
        }), 200

    # Otherwise check Discord API
    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    resp = requests.get(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers=bot_headers,
        timeout=10
    )

    if resp.status_code == 404:
        return jsonify({
            "ok": False,
            "role_granted": False,
            "message": "You're not in the Discord server. Join and verify first."
        }), 404

    if resp.status_code != 200:
        return jsonify({
            "ok": False,
            "role_granted": False,
            "message": f"Discord API error {resp.status_code}. Try again later."
        }), resp.status_code

    data = resp.json()
    roles = data.get("roles", [])
    if str(DISCORD_ROLE_ID) in [str(r) for r in roles]:
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "Subscriber role verified."
        }), 200
    else:
        return jsonify({
            "ok": True,
            "role_granted": False,
            "message": "Subscriber role not found. Subscribe on YouTube and complete Discord verification."
        }), 200


# ─────────────────────────────────────────────
# Global Admin Override API
# ─────────────────────────────────────────────
@app.route("/override/all", methods=["GET"])
def get_override_all():
    """Check if global override is active."""
    key = request.args.get("key")
    admin_key = os.getenv("ADMIN_PANEL_KEY", os.getenv("SECRET_KEY", ""))
    if admin_key and key != admin_key:
        return jsonify({"ok": False, "message": "Unauthorized"}), 403
    return jsonify({"ok": True, "override_all": global_override}), 200


@app.route("/override/all", methods=["POST"])
def set_override_all():
    """Enable global override (requires ?key=SECRET)."""
    global global_override
    key = request.args.get("key")
    admin_key = os.getenv("ADMIN_PANEL_KEY", os.getenv("SECRET_KEY", ""))
    if admin_key and key != admin_key:
        return jsonify({"ok": False, "message": "Unauthorized"}), 403
    global_override = True
    return jsonify({"ok": True, "message": "Global override enabled"}), 200


@app.route("/override/all", methods=["DELETE"])
def clear_override_all():
    """Disable global override (requires ?key=SECRET)."""
    global global_override
    key = request.args.get("key")
    admin_key = os.getenv("ADMIN_PANEL_KEY", os.getenv("SECRET_KEY", ""))
    if admin_key and key != admin_key:
        return jsonify({"ok": False, "message": "Unauthorized"}), 403
    global_override = False
    return jsonify({"ok": True, "message": "Global override disabled"}), 200


# ─────────────────────────────────────────────
# Per-user Admin Override API
# ─────────────────────────────────────────────
@app.route("/override/<discord_id>", methods=["GET"])
def get_override(discord_id):
    """Check if override is active for a specific user."""
    return jsonify({
        "ok": True,
        "admin_override": bool(admin_overrides.get(discord_id, False))
    })


@app.route("/override/<discord_id>", methods=["POST"])
def set_override(discord_id):
    """Enable override for a specific user (requires ?key=SECRET)."""
    key = request.args.get("key")
    admin_key = os.getenv("ADMIN_PANEL_KEY", os.getenv("SECRET_KEY", ""))
    if admin_key and key != admin_key:
        return jsonify({"ok": False, "message": "Unauthorized"}), 403

    admin_overrides[discord_id] = True
    return jsonify({"ok": True, "message": f"Override enabled for {discord_id}"}), 200


@app.route("/override/<discord_id>", methods=["DELETE"])
def clear_override(discord_id):
    """Disable override for a specific user (requires ?key=SECRET)."""
    key = request.args.get("key")
    admin_key = os.getenv("ADMIN_PANEL_KEY", os.getenv("SECRET_KEY", ""))
    if admin_key and key != admin_key:
        return jsonify({"ok": False, "message": "Unauthorized"}), 403

    admin_overrides[discord_id] = False
    return jsonify({"ok": True, "message": f"Override disabled for {discord_id}"}), 200

# ─────────────────────────────────────────────
# Role cleanup — remove subscriber role from everyone who has it
# ─────────────────────────────────────────────
@app.route("/remove_roles_now")
def remove_roles_now():
    """
    Scans all guild members and removes the subscriber role from anyone who has it.
    Works even if roles were assigned manually.
    """
    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }

    removed = 0
    after = None
    while True:
        url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000"
        if after:
            url += f"&after={after}"

        r = requests.get(url, headers=bot_headers, timeout=20)
        try:
            members = r.json()
        except Exception:
            return render_template_string(ERROR_HTML, message="Failed to parse member list."), 500

        if not members:
            break

        for m in members:
            after = m["user"]["id"]
            if str(DISCORD_ROLE_ID) in [str(r) for r in m.get("roles", [])]:
                rr = requests.delete(
                    f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{m['user']['id']}/roles/{DISCORD_ROLE_ID}",
                    headers=bot_headers,
                    timeout=10
                )
                if rr.status_code == 204:
                    removed += 1

        if len(members) < 1000:
            break

    return render_template_string(f"""
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Roles Removed</title>
{BASE_STYLE}
</head><body>
<section class="hero"><div class="box">
<div class="msg success">✅ Removed subscriber role from {removed} member(s)</div>
<div class="subtitle">Cleanup complete. You may now close this window.</div>
</div></section>
</body></html>
"""), 200

# ─────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────
if __name__ == "__main__":
    logging.info("Starting server…")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))