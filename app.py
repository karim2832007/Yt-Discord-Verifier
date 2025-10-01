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
    Flask, redirect, request, session,
    jsonify, render_template_string
)
from dotenv import load_dotenv

# ------------------------------------------------------------------------------
# Config and Setup
# ------------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Enforce 1-day permanent sessions
app.permanent_session_lifetime = timedelta(days=1)
app.config.update(
    SESSION_COOKIE_DOMAIN=".gaming-mods.com",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Main site URL to redirect after login
MAIN_SITE_URL = os.environ.get("MAIN_SITE_URL", "https://gaming-mods.com").rstrip("/")

# Discord OAuth credentials and settings
DISCORD_CLIENT_ID     = os.environ["DISCORD_CLIENT_ID"]
DISCORD_CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
DISCORD_GUILD_ID      = os.environ["DISCORD_GUILD_ID"]
DISCORD_ROLE_ID       = os.environ["DISCORD_ROLE_ID"]
DISCORD_BOT_TOKEN     = os.environ["DISCORD_BOT_TOKEN"]

# Admin key for override endpoints
ADMIN_PANEL_KEY = os.environ.get("ADMIN_PANEL_KEY", "")

# Override storage (in-memory)
global_override  = False
admin_overrides  = {}   # { discord_id (str): True }

# State TTL for CSRF tokens
STATE_TTL = 15 * 60  # 15 minutes

# Logging
logging.basicConfig(level=logging.INFO)
app.config["PROPAGATE_EXCEPTIONS"] = True


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def now() -> int:
    return int(time.time())


def sign_state(payload: str) -> str:
    key = app.secret_key.encode()
    sig = hmac.new(key, payload.encode(), hashlib.sha256).digest()
    token = f"{payload}|{base64.urlsafe_b64encode(sig).decode()}"
    return base64.urlsafe_b64encode(token.encode()).decode()


def verify_state(token: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        payload, sig_b64 = raw.split("|", 1)
        nonce, ts_str = payload.split(".", 1)
        if now() - int(ts_str) > STATE_TTL:
            return False
        key = app.secret_key.encode()
        expected = hmac.new(key, payload.encode(), hashlib.sha256).digest()
        given    = base64.urlsafe_b64decode(sig_b64.encode())
        return hmac.compare_digest(expected, given)
    except Exception:
        return False


def make_state() -> str:
    payload = f"{secrets.token_hex(8)}.{now()}"
    return sign_state(payload)


def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    resp = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id":     DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "code":          code,
            "redirect_uri":  redirect_uri,
            "grant_type":    "authorization_code",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20
    )
    return resp.json()


def discord_get_user(access_token: str) -> dict:
    return requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20
    ).json()


def discord_get_member(discord_id: str) -> dict:
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=20
    )
    if resp.status_code == 200:
        return resp.json()
    return {"status_code": resp.status_code, "error": resp.text}


def discord_has_role(member: dict) -> bool:
    return str(DISCORD_ROLE_ID) in [str(r) for r in member.get("roles", [])]


def discord_add_role(discord_id: str) -> bool:
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}/roles/{DISCORD_ROLE_ID}"
    resp = requests.put(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=20
    )
    return resp.status_code in (200, 204)


def should_assign_role_on_login(did: str) -> bool:
    if global_override:
        return True
    return bool(admin_overrides.get(did))


def require_admin_key() -> bool:
    return request.args.get("key") == ADMIN_PANEL_KEY


# ------------------------------------------------------------------------------
# Error handler
# ------------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_error(e):
    logging.exception("Unhandled exception:")
    return jsonify({"ok": False, "error": str(e)}), 500


# ------------------------------------------------------------------------------
# Discord OAuth: login & callbacks
# ------------------------------------------------------------------------------
@app.route("/login/discord")
def discord_login():
    state = make_state()
    redirect_uri = f"{request.url_root.rstrip('/')}/login/discord/callback"
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
    code  = request.args.get("code", "")
    if not state or not verify_state(state):
        return "Invalid or expired state", 400
    if not code:
        return "Discord auth failed", 400

    redirect_uri_used = request.base_url
    token = discord_exchange_token(code, redirect_uri_used)
    if "access_token" not in token:
        return "Discord auth failed", 400

    user = discord_get_user(token["access_token"])
    did  = str(user.get("id", "")) or ""
    if not did:
        return "Discord user not found", 400

    # Optionally assign role
    assigned = False
    try:
        if should_assign_role_on_login(did):
            assigned = discord_add_role(did)
    except Exception:
        assigned = False

    # Set permanent session
    session.permanent = True
    session["user"] = {
        "id":            did,
        "username":      user.get("username", ""),
        "discriminator": user.get("discriminator", ""),
        "ts":            now()
    }

    # Render copy-ID gate
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Confirm Your Discord ID</title>
  <style>
    body { background:#0a0a0a; color:#eee; font-family:'Segoe UI',sans-serif;
           display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
    .card { background:rgba(0,0,0,0.6); padding:2rem; border-radius:12px;
            box-shadow:0 0 20px rgba(0,0,0,0.7); text-align:center; max-width:500px; }
    h2 { color:#FFD700; margin-bottom:0.5rem; text-shadow:0 0 10px #B8860B; }
    p { color:#ccc; }
    .id { font-size:1.2rem; margin:1rem 0; color:#fff; }
    .row { display:flex; gap:0.75rem; justify-content:center; margin-top:1rem; }
    button { padding:0.75rem 1.25rem; border:none; border-radius:8px;
             cursor:pointer; font-weight:bold; color:#fff; background:#111;
             box-shadow:0 0 10px #444; transition:transform .2s; }
    button:hover { transform:scale(1.04); }
    .primary { box-shadow:0 0 10px #0f0; }
    .disabled { opacity:0.6; cursor:not-allowed; box-shadow:none; }
    .ok { color:#8ef18e; margin-top:0.5rem; display:none; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Login successful.</h2>
    {% if assigned %}<p class="ok">Role assigned successfully.</p>{% endif %}
    <p class="id">Your Discord ID: <b id="did">{{ did }}</b></p>
    <div class="row">
      <button id="copy" class="primary">Copy ID</button>
      <button id="continue" class="disabled" disabled>Continue</button>
    </div>
  </div>

  <script>
    const did = document.getElementById("did").textContent.trim();
    const copyBtn = document.getElementById("copy");
    const contBtn = document.getElementById("continue");
    const okMsg   = document.querySelector(".ok");

    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(did);
        copyBtn.textContent = "Copied!";
        contBtn.removeAttribute("disabled");
        contBtn.classList.remove("disabled");
        if (okMsg) okMsg.style.display = "block";
      } catch {
        alert("Copy failed. Please select and copy manually.");
      }
    });

    contBtn.addEventListener("click", () => {
      if (contBtn.hasAttribute("disabled")) return;
      window.location.href = "{{ main_url }}/index.html?discord_id=" + did;
    });
  </script>
</body>
</html>
    """, did=did, assigned=assigned, main_url=MAIN_SITE_URL)


@app.route("/login/discord/callback")
def cb_login_path():
    return _discord_callback()

@app.route("/discord/callback")
def cb_plain_path():
    return _discord_callback()


# ------------------------------------------------------------------------------
# Status and override-aware role check
# ------------------------------------------------------------------------------
@app.route("/status/<discord_id>")
def status(discord_id):
    did = str(discord_id)

    if global_override:
        return jsonify({"ok": True, "role_granted": True,  "message": "⚡ Global override active"}), 200

    if admin_overrides.get(did):
        return jsonify({"ok": True, "role_granted": True, "message": "⚡ Admin override active"}), 200

    member = discord_get_member(did)
    if "roles" in member:
        has = discord_has_role(member)
        msg = "Subscriber role verified." if has else "Subscriber role not found."
        return jsonify({"ok": True, "role_granted": bool(has), "message": msg}), 200

    code = member.get("status_code", 404)
    return jsonify({
        "ok": False,
        "role_granted": False,
        "message": f"Member not found or error (HTTP {code})."
    }), 404


# ------------------------------------------------------------------------------
# Admin override endpoints
# ------------------------------------------------------------------------------
@app.route("/override/all", methods=["GET", "POST", "DELETE"])
def override_all():
    global global_override
    if request.method == "GET":
        return jsonify({"ok": True, "global_override": global_override}), 200

    if not require_admin_key():
        return jsonify({"ok": False, "message": "Forbidden."}), 403

    if request.method == "POST":
        global_override = True
        return jsonify({"ok": True, "message": "Global override enabled"}), 200

    if request.method == "DELETE":
        global_override = False
        return jsonify({"ok": True, "message": "Global override disabled"}), 200

    return jsonify({"ok": False, "message": "Method not allowed"}), 405


@app.route("/override/<discord_id>", methods=["GET", "POST", "DELETE"])
def override_user(discord_id):
    did = str(discord_id)

    if request.method == "GET":
        return jsonify({"ok": True, "user_override": bool(admin_overrides.get(did)), "discord_id": did}), 200

    if not require_admin_key():
        return jsonify({"ok": False, "message": "Forbidden."}), 403

    if request.method == "POST":
        admin_overrides[did] = True
        return jsonify({"ok": True, "message": f"Override enabled for {did}"}), 200

    if request.method == "DELETE":
        admin_overrides.pop(did, None)
        return jsonify({"ok": True, "message": f"Override disabled for {did}"}), 200

    return jsonify({"ok": False, "message": "Method not allowed"}), 405


@app.route("/override", methods=["GET"])
def list_overrides():
    if not require_admin_key():
        return jsonify({"ok": False, "message": "Forbidden."}), 403
    return jsonify({
        "ok": True,
        "global_override": global_override,
        "users": sorted(admin_overrides.keys())
    }), 200


# ------------------------------------------------------------------------------
# Session helpers
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
    return jsonify({"ok": True, "message": "Logged out"}), 200


# ------------------------------------------------------------------------------
# Health check
# ------------------------------------------------------------------------------
@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": now()}), 200


# ------------------------------------------------------------------------------
# Run (for local dev)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)