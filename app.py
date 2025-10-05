import os
import time
import secrets
import hmac
import hashlib
import base64
import logging
from datetime import timedelta
import requests
from flask import (
    Flask, redirect, request, session, jsonify, render_template_string
)
from dotenv import load_dotenv
from flask_cors import CORS
import json

# ------------------------------------------------------------------------------
# Load environment and configure app
# ------------------------------------------------------------------------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=1)
app.config.update(
    SESSION_COOKIE_DOMAIN=".gaming-mods.com",  # allows cookies across verifier and main domain
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
)

CORS(app, origins=["https://gaming-mods.com"], supports_credentials=True)

# ------------------------------------------------------------------------------
# Discord & Owner settings
# ------------------------------------------------------------------------------
DISCORD_CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
DISCORD_CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
DISCORD_GUILD_ID = os.environ["DISCORD_GUILD_ID"]
DISCORD_ROLE_ID = os.environ["DISCORD_ROLE_ID"]
DISCORD_BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]
OWNER_ID = "1329817290052734980"  # your Discord ID

# Enforced redirect URI for OAuth (must match Discord portal)
DISCORD_REDIRECT = os.environ.get("DISCORD_REDIRECT", "").strip()

# IONOS front end URLs (use these for redirects)
IONOS_BASE = os.environ.get("BASE_URL", "https://gaming-mods.com").rstrip("/")
IONOS_INDEX = f"{IONOS_BASE}/index.html" if not IONOS_BASE.endswith("/") else IONOS_BASE
IONOS_ADMIN = f"{IONOS_BASE}/admin.html"
IONOS_GAMES = f"{IONOS_BASE}/games.html"
IONOS_DONATE = f"{IONOS_BASE}/donate.html"
IONOS_PRIVACY = f"{IONOS_BASE}/privacy.html"

# ------------------------------------------------------------------------------
# In-memory override state
# ------------------------------------------------------------------------------
global_override = False
admin_overrides = {}
login_history = []

# ------------------------------------------------------------------------------
# Persistent override state (JSON file)
# ------------------------------------------------------------------------------
STATE_FILE = "override_state.json"

def save_state():
    with open(STATE_FILE, "w") as f:
        json.dump({
            "global_override": global_override,
            "admin_overrides": admin_overrides
        }, f)

def load_state():
    global global_override, admin_overrides
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            data = json.load(f)
        global_override = data.get("global_override", False)
        admin_overrides = data.get("admin_overrides", {})

load_state()

# ------------------------------------------------------------------------------
# CSRF–state TTL and logging
# ------------------------------------------------------------------------------
STATE_TTL = 15 * 60
logging.basicConfig(level=logging.INFO)
app.config["PROPAGATE_EXCEPTIONS"] = True

# ------------------------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------------------------
def now_ts() -> int:
    return int(time.time())

def sign_state(payload: str) -> str:
    key = app.secret_key.encode()
    sig = hmac.new(key, payload.encode(), hashlib.sha256).digest()
    token = f"{payload}|{base64.urlsafe_b64encode(sig).decode()}"
    return base64.urlsafe_b64encode(token.encode()).decode()

def verify_state(token: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(token).decode()
        payload, sig_b64 = raw.split("|", 1)
        _, ts_str = payload.split(".", 1)
        if now_ts() - int(ts_str) > STATE_TTL:
            return False
        key = app.secret_key.encode()
        expected = hmac.new(key, payload.encode(), hashlib.sha256).digest()
        given = base64.urlsafe_b64decode(sig_b64)
        return hmac.compare_digest(expected, given)
    except Exception:
        return False

def make_state() -> str:
    payload = f"{secrets.token_hex(8)}.{now_ts()}"
    return sign_state(payload)

def require_owner() -> bool:
    user = session.get("user")
    return bool(user and user.get("id") == OWNER_ID)

# ------------------------------------------------------------------------------
# Shared headers for Discord requests
# ------------------------------------------------------------------------------
DEFAULT_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "GamingMods-Verifier/1.0 (+https://gaming-mods.com)"
}

# ------------------------------------------------------------------------------
# Discord API helpers
# ------------------------------------------------------------------------------
def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    resp = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        },
        headers=DEFAULT_HEADERS,
        timeout=15
    )
    if resp.status_code == 429:
        time.sleep(1.5)
        resp = requests.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers=DEFAULT_HEADERS,
            timeout=15
        )
    try:
        data = resp.json()
    except Exception:
        data = {}
    if resp.status_code != 200:
        return {
            "error": "token_exchange_failed",
            "status": resp.status_code,
            "body": resp.text or "",
            "json": data
        }
    return data

def discord_get_user(token: str) -> dict:
    resp = requests.get(
        "https://discord.com/api/users/@me",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "GamingMods-Verifier/1.0 (+https://gaming-mods.com)"
        },
        timeout=15
    )
    try:
        data = resp.json()
    except Exception:
        data = {}
    if resp.status_code != 200:
        return {
            "error": "user_fetch_failed",
            "status": resp.status_code,
            "body": resp.text or "",
            "json": data
        }
    return data

def discord_member(did: str) -> dict:
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=15
    )
    if resp.status_code == 200:
        return resp.json()
    return {"status_code": resp.status_code, "error": resp.text}

def discord_has_role(member: dict) -> bool:
    return str(DISCORD_ROLE_ID) in [str(r) for r in member.get("roles", [])]

def discord_add_role(did: str) -> bool:
    url = (
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}"
        f"/members/{did}/roles/{DISCORD_ROLE_ID}"
    )
    resp = requests.put(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=15
    )
    return resp.status_code in (200, 204)

def discord_remove_role(did: str) -> bool:
    url = (
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}"
        f"/members/{did}/roles/{DISCORD_ROLE_ID}"
    )
    resp = requests.delete(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=15
    )
    return resp.status_code in (200, 204)

def should_assign_on_login(did: str) -> bool:
    return global_override or admin_overrides.get(did, False)

# ------------------------------------------------------------------------------
# Error handler
# ------------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_exception(e):
    logging.exception("Unhandled exception:")
    return jsonify({"ok": False, "error": str(e)}), 500

# ------------------------------------------------------------------------------
# Use IONOS front end via redirects (no local static serving)
# ------------------------------------------------------------------------------
@app.route("/")
def serve_index():
    # Always use the IONOS homepage
    return redirect(IONOS_BASE)

@app.route("/admin")
def serve_admin():
    # If you want to gate access, keep owner check; else remove
    if not require_owner():
        return "Forbidden", 403
    return redirect(IONOS_ADMIN)

@app.route("/games")
def serve_games():
    return redirect(IONOS_GAMES)

@app.route("/privacy")
def serve_privacy():
    return redirect(IONOS_PRIVACY)

@app.route("/donate")
def serve_donate():
    return redirect(IONOS_DONATE)

@app.route("/admin/logins")
def admin_logins():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    return jsonify({"ok": True, "logins": login_history}), 200

# ------------------------------------------------------------------------------
# Discord OAuth flow
# ------------------------------------------------------------------------------
@app.route("/login/discord")
def login_discord():
    state = make_state()
    # Always use the env var; fallback derived only if missing
    redirect_uri = DISCORD_REDIRECT or f"{request.url_root.rstrip('/')}/login/discord/callback"
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code&scope=identify"
        f"&state={state}"
    )
    return redirect(auth_url)

def _discord_callback():
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    if not state or not verify_state(state):
        return "Invalid or expired state", 400
    if not code:
        return "Missing code", 400

    # Use the same exact redirect URI string for token exchange
    redirect_uri = DISCORD_REDIRECT or request.base_url
    token_resp = discord_exchange_token(code, redirect_uri)

    if "access_token" not in token_resp:
        return jsonify({"ok": False, "message": "Token exchange failed", "details": token_resp}), 400

    user_info = discord_get_user(token_resp["access_token"])
    did = str(user_info.get("id", "") or "")
    if not did:
        return jsonify({"ok": False, "message": "Discord user lookup failed", "details": user_info}), 400

    try:
        if should_assign_on_login(did):
            discord_add_role(did)
    except Exception:
        pass

    session.permanent = True
    session["user"] = {
        "id": did,
        "username": user_info.get("username", ""),
        "discriminator": user_info.get("discriminator", ""),
        "ts": now_ts()
    }
    login_history.append(session["user"])

    # ID copy gate page (served by backend), then send to IONOS front end
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Confirm Your Discord ID</title>
<style>
  body{background:#0a0a0a;color:#eee;font-family:'Segoe UI',sans-serif;
       display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
  .card{background:rgba(0,0,0,0.6);padding:2rem;border-radius:12px;
       box-shadow:0 0 20px rgba(0,0,0,0.7);text-align:center;max-width:500px}
  h2{color:#FFD700;margin-bottom:.5rem}
  p{color:#ccc}.id{font-size:1.2rem;margin:1rem 0;color:#fff}
  .row{display:flex;gap:.75rem;justify-content:center;margin-top:1rem}
  button{padding:.75rem 1.25rem;border:none;border-radius:8px;
       cursor:pointer;font-weight:bold;color:#fff;background:#111;
       box-shadow:0 0 10px #444;transition:transform .2s}
  button:hover{transform:scale(1.04)}.primary{box-shadow:0 0 10px #0f0}
  .disabled{opacity:.6;cursor:not-allowed}
</style>
</head>
<body>
  <div class="card">
    <h2>Login successful.</h2>
    <p class="id">Your Discord ID: <b id="did">{{ did }}</b></p>
    <div class="row">
      <button id="copy" class="primary">Copy ID</button>
      <button id="continue" class="disabled" disabled>Continue</button>
    </div>
  </div>
<script>
  const did = document.getElementById('did').textContent.trim();
  const copyBtn = document.getElementById('copy');
  const contBtn = document.getElementById('continue');
  copyBtn.addEventListener('click', async () => {
    await navigator.clipboard.writeText(did);
    copyBtn.textContent = 'Copied!';
    contBtn.disabled = false;
    contBtn.classList.remove('disabled');
  });
  contBtn.addEventListener('click', () => {
    if (!contBtn.disabled) {
      window.location.href = '{{ ionos_base }}' + ({{ has_index }} ? '/index.html' : '');
      // Pass id as query param if your IONOS front end expects it:
      // window.location.href = '{{ ionos_base }}' + '?discord_id=' + encodeURIComponent(did);
    }
  });
</script>
</body>
</html>
""", did=did, ionos_base=IONOS_BASE, has_index=(not IONOS_BASE.endswith("/")))

@app.route("/login/discord/callback")
def discord_callback_login():
    return _discord_callback()

@app.route("/discord/callback")
def discord_callback_plain():
    return _discord_callback()

# ------------------------------------------------------------------------------
# Session, Status, Logout, Health
# ------------------------------------------------------------------------------
@app.route("/portal/me")
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({"ok": True, "user": user}), 200

@app.route("/logout")
def logout():
    session.clear()
    return redirect(IONOS_BASE)

@app.route("/status/<did>")
def status(did):
    if global_override:
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "🌍 GLOBAL OVERRIDE ACTIVE — All players have been granted access by the Admin Council!"
        }), 200
    if admin_overrides.get(did):
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "👑 ADMIN OVERRIDE — Your account has been hand‑picked and empowered with unlimited access!"
        }), 200

    member = discord_member(did)
    if "roles" in member:
        has = discord_has_role(member)
        msg = "✨ Subscriber role verified — welcome, honored supporter!" if has else "❌ Subscriber role not found — verify your YouTube subscription."
        return jsonify({"ok": True, "role_granted": has, "message": msg}), 200

    return jsonify({
        "ok": False,
        "role_granted": False,
        "message": f"⚠️ Member error (status {member.get('status_code')})"
    }), 404

@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": now_ts()}), 200

# ------------------------------------------------------------------------------
# Override Endpoints (Owner Only)
# ------------------------------------------------------------------------------
@app.route("/override/all", methods=["GET", "POST", "DELETE"])
def override_all():
    global global_override
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403

    if request.method == "GET":
        return jsonify({"ok": True, "global_override": global_override}), 200

    if request.method == "POST":
        global_override = True
        save_state()
        return jsonify({"ok": True, "global_override": True}), 200

    if request.method == "DELETE":
        global_override = False
        save_state()
        return jsonify({"ok": True, "global_override": False}), 200

    return jsonify({"ok": False, "message": "Method not allowed"}), 405

@app.route("/override/<did>", methods=["GET", "POST", "DELETE"])
def override_user(did):
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403

    if request.method == "GET":
        return jsonify({
            "ok": True,
            "user_override": bool(admin_overrides.get(did)),
            "discord_id": did
        }), 200

    if request.method == "POST":
        admin_overrides[did] = {"username": "", "discriminator": ""}
        save_state()
        return jsonify({"ok": True, "user_override": True, "discord_id": did}), 200

    if request.method == "DELETE":
        admin_overrides.pop(did, None)
        save_state()
        return jsonify({"ok": True, "user_override": False, "discord_id": did}), 200

    return jsonify({"ok": False, "message": "Method not allowed"}), 405

@app.route("/override", methods=["GET"])
def list_overrides():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    users = []
    for did, info in admin_overrides.items():
        users.append({
            "id": did,
            "username": info.get("username", ""),
            "discriminator": info.get("discriminator", "")
        })
    return jsonify({
        "ok": True,
        "global_override": global_override,
        "users": users
    }), 200

# ------------------------------------------------------------------------------
# Immediate Role Removal Endpoint (Owner Only)
# ------------------------------------------------------------------------------
@app.route("/remove_role_now/<did>", methods=["POST"])
def remove_role_now(did):
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    success = discord_remove_role(did)
    status_code = 200 if success else 500
    return jsonify({"ok": success, "discord_id": did}), status_code

@app.route("/remove_role_all", methods=["POST"])
def remove_role_all():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        return jsonify({"ok": False, "message": "Failed to fetch members"}), 500
    members = resp.json()
    removed, failed = [], []
    for m in members:
        did = str(m["user"]["id"])
        r = requests.delete(
            f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}",
            headers=headers,
            timeout=15
        )
        if r.status_code in (200, 204):
            removed.append(did)
        else:
            failed.append(did)
    return jsonify({
        "ok": True,
        "removed_count": len(removed),
        "failed_count": len(failed),
        "removed_sample": removed[:10],
        "failed_sample": failed[:10]
    }), 200

# ------------------------------------------------------------------------------
# Run server
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
