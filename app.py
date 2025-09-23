import os
import time
import requests
from dotenv import load_dotenv
from flask import (
    Flask, request, redirect,
    jsonify, render_template_string, url_for
)

#───────────────────────────────────────────────────────────────────────────────
# Load environment
#───────────────────────────────────────────────────────────────────────────────
load_dotenv()
app = Flask(__name__)

BASE_URL            = os.environ["BASE_URL"].rstrip("/")
DISCORD_CLIENT_ID     = os.environ["DISCORD_CLIENT_ID"]
DISCORD_CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
DISCORD_REDIRECT      = os.environ["DISCORD_REDIRECT"]
DISCORD_GUILD_ID      = os.environ["DISCORD_GUILD_ID"]
DISCORD_ROLE_ID       = os.environ["DISCORD_ROLE_ID"]
DISCORD_BOT_TOKEN     = os.environ["DISCORD_BOT_TOKEN"]

ACTIVATION_TTL     = 24 * 60 * 60   # seconds

# store pending activations by Ren’Py code
pending_activations = {}

#───────────────────────────────────────────────────────────────────────────────
# Success / Error Page Templates
#───────────────────────────────────────────────────────────────────────────────
def _success_page():
    return """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Success</title>
<link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
<style>
  body, html { width:100%; height:100%; margin:0; background:#000; color:#0f0;
    display:flex; align-items:center; justify-content:center;
    font-family:'Segoe UI',sans-serif; }
  .box { text-align:center; }
  .msg { font-size:2rem; text-shadow:0 0 10px #0f0; }
</style>
</head><body>
  <div class="box">
    <p class="msg">✅ Success! You have the subscriber role.</p>
    <p>You can close this tab.</p>
  </div>
</body></html>
"""

def _error_page():
    return """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Error</title>
<link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
<style>
  body, html { width:100%; height:100%; margin:0; background:#000; color:#f00;
    display:flex; align-items:center; justify-content:center;
    font-family:'Segoe UI',sans-serif; }
  .box { text-align:center; }
  .msg { font-size:2rem; text-shadow:0 0 10px #f00; }
</style>
</head><body>
  <div class="box">
    <p class="msg">❌ {{ message }}</p>
    <p>Please try again or contact support.</p>
  </div>
</body></html>
"""

#───────────────────────────────────────────────────────────────────────────────
# 1) Discord OAuth Login Page (styled like landing)
#───────────────────────────────────────────────────────────────────────────────
@app.route("/discord/login")
def discord_login():
    code = request.args.get("code")
    if not code:
        return "Missing activation code", 400

    state = code
    discord_auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        "&response_type=code"
        "&scope=identify%20guilds.members.read"
        f"&state={state}"
    )

    return render_template_string("""
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Gaming Mods Membership</title>
<link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body, html { width:100%; height:100%; overflow:hidden;
    background:#0a0a0a; font-family:'Segoe UI',sans-serif; color:#eee; }
  .hero { position:relative; width:100%; height:100vh;
    display:flex; flex-direction:column; align-items:center; justify-content:center;
    background: radial-gradient(circle at center, #111 0%, #000 80%); }
  .hero::before { content:""; position:absolute; top:0; left:0; width:100%; height:100%;
    background: url('{{ url_for("static", filename="holo-grid.png") }}') center/cover;
    opacity:.1; animation:holoShift 20s linear infinite; }
  @keyframes holoShift { from{background-position:0 0;} to{background-position:1000px 1000px;} }
  .hero-title { z-index:1; font-size:4rem; font-weight:bold; font-style:italic;
    color:#FFD700; text-shadow:0 0 10px #B8860B,0 0 20px #B8860B,0 0 30px #FFD700;
    animation:fadeInDown 1.5s ease-out; }
  @keyframes fadeInDown { from{opacity:0; transform:translateY(-50px);} to{opacity:1; transform:translateY(0);} }
  .hero-subtitle { z-index:1; margin-top:1rem; font-size:1.25rem; max-width:700px; text-align:center;
    color:#ccc; animation:fadeIn 2s ease-in-out; }
  @keyframes fadeIn { from{opacity:0;} to{opacity:1;} }
  .cta-btn { z-index:1; margin-top:2rem; padding:1rem 2rem; font-size:1.2rem; font-weight:bold;
    background: rgba(255,255,255,0.1); color:#fff; border:2px solid #fff; border-radius:8px;
    cursor:pointer; transition: transform .3s ease, box-shadow .3s ease;
    animation:fadeInUp 1.5s ease-out; }
  .cta-btn:hover { transform:scale(1.05); box-shadow:0 0 15px rgba(255,255,255,0.5); }
  @keyframes fadeInUp { from{opacity:0; transform:translateY(50px);} to{opacity:1; transform:translateY(0);} }
</style>
</head><body>
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
</body></html>
""", discord_url=discord_auth_url)

#───────────────────────────────────────────────────────────────────────────────
# 2) Discord OAuth Callback & Role Check
#───────────────────────────────────────────────────────────────────────────────
@app.route("/discord/callback")
def discord_callback():
    state     = request.args.get("state")
    code_param= request.args.get("code")
    if not state or not code_param:
        return render_template_string(_error_page(), message="Invalid OAuth flow.")

    # Exchange code for access token
    token = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id":     DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type":    "authorization_code",
            "code":          code_param,
            "redirect_uri":  DISCORD_REDIRECT
        },
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        timeout=20
    ).json()
    if "access_token" not in token:
        return render_template_string(_error_page(), message="Discord auth failed.")

    # Fetch Discord user ID
    user   = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization":f"Bearer {token['access_token']}"},
        timeout=20
    ).json()
    user_id = user.get("id")
    if not user_id:
        return render_template_string(_error_page(), message="Failed to fetch Discord user.")

    # Check guild membership & roles
    member = requests.get(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user_id}",
        headers={"Authorization":f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=20
    )
    if member.status_code != 200:
        return render_template_string(_error_page(), message="Not in server.")
    roles = member.json().get("roles", [])

    # Verify subscriber role
    if DISCORD_ROLE_ID not in roles:
        return render_template_string(_error_page(), message="You do not have the subscriber role.")

    # Record activation
    pending_activations[state] = {"activated_at": time.time()}
    return render_template_string(_success_page())

#───────────────────────────────────────────────────────────────────────────────
# 3) Ren’Py Polling Endpoint
#───────────────────────────────────────────────────────────────────────────────
@app.route("/has_role_recent")
def has_role_recent():
    code  = request.args.get("code")
    entry = pending_activations.get(code)
    if not entry:
        return jsonify({"ok": False, "has_role": False}), 404

    expired = (time.time() - entry["activated_at"]) > ACTIVATION_TTL
    return jsonify({"ok": True, "has_role": not expired}), 200

#───────────────────────────────────────────────────────────────────────────────
# 4) (Optional) Role Cleanup
#───────────────────────────────────────────────────────────────────────────────
@app.route("/remove_roles_now")
def remove_roles_now():
    return "Cleanup not implemented", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
