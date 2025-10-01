from flask import Flask, redirect, request, session, jsonify, render_template_string
import os
import time
import secrets
import string
import requests
import logging
import hmac
import hashlib
import base64
from dotenv import load_dotenv

# ------------------------------------------------------------------------------
# Config and setup
# ------------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Branding / redirects
MAIN_SITE_URL = os.environ.get("MAIN_SITE_URL", "https://gaming-mods.com").rstrip("/")

# Discord
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
# IMPORTANT: Register this callback in Discord Developer Portal
# e.g. https://verifier.gaming-mods.com/login/discord/callback
DISCORD_REDIRECT = os.environ.get("DISCORD_REDIRECT", "").rstrip("/")
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")

# Admin panel key (for override endpoints)
ADMIN_PANEL_KEY = os.environ.get("ADMIN_PANEL_KEY", "")

# Settings
STATE_TTL = 15 * 60   # 15 minutes window for OAuth state
CODE_TTL  = 15 * 60   # if you use codes anywhere else

# Override stores (in-memory)
global_override = False
admin_overrides = {}  # { discord_id(str): True }

# Logging
logging.basicConfig(level=logging.INFO)
app.config["PROPAGATE_EXCEPTIONS"] = True


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def now() -> int:
    return int(time.time())


def gen_code(n=6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))


def sign_state(payload: str) -> str:
    """Create HMAC-SHA256 signature and produce a compact token: base64(payload|sig)."""
    key = app.secret_key.encode("utf-8")
    sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).digest()
    token = f"{payload}|{base64.urlsafe_b64encode(sig).decode('utf-8')}"
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("utf-8")


def verify_state(token: str) -> bool:
    """Verify token integrity and TTL."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        payload, sig_b64 = raw.split("|", 1)
        # payload format: nonce.ts
        nonce, ts_str = payload.split(".", 1)
        ts = int(ts_str)
        if now() - ts > STATE_TTL:
            return False
        # recompute signature
        key = app.secret_key.encode("utf-8")
        expected_sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).digest()
        given_sig = base64.urlsafe_b64decode(sig_b64.encode("utf-8"))
        return hmac.compare_digest(expected_sig, given_sig)
    except Exception:
        return False


def make_state() -> str:
    """Generate stateless state token with nonce + timestamp, HMAC-signed."""
    payload = f"{secrets.token_hex(8)}.{now()}"
    return sign_state(payload)


def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    resp = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    return resp.json()


def discord_get_user(access_token: str) -> dict:
    resp = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20,
    )
    return resp.json()


def discord_get_member(discord_id: str) -> dict:
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=20,
    )
    if resp.status_code == 200:
        return resp.json()
    return {"status_code": resp.status_code, "error": resp.text}


def discord_has_role(member_json: dict) -> bool:
    roles = member_json.get("roles", [])
    return str(DISCORD_ROLE_ID) in [str(r) for r in roles]


def discord_add_role(discord_id: str) -> bool:
    """Assign the verification role (best effort). Requires the user to be in the guild."""
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}/roles/{DISCORD_ROLE_ID}"
    resp = requests.put(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=20,
    )
    return resp.status_code in (204, 200)


def require_admin_key() -> bool:
    key = request.args.get("key")
    return bool(ADMIN_PANEL_KEY) and key == ADMIN_PANEL_KEY


# ------------------------------------------------------------------------------
# Error handler
# ------------------------------------------------------------------------------
@app.errorhandler(Exception)
def on_error(e):
    logging.exception("Unhandled exception in route:")
    return jsonify({"ok": False, "error": str(e)}), 500


# ------------------------------------------------------------------------------
# Minimal home (optional)
# ------------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template_string(
        """
        <h2>Discord Login</h2>
        <p>This backend handles Discord OAuth and admin overrides.</p>
        <a href="/login/discord">Login with Discord</a>
        """
    )


# ------------------------------------------------------------------------------
# Discord OAuth (standalone site login — no Google required)
# ------------------------------------------------------------------------------
@app.route("/login/discord")
def discord_login():
    # Stateless CSRF state token
    state = make_state()
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        f"&response_type=code&scope=identify"
        f"&state={state}"
    )
    return redirect(auth_url)


@app.route("/login/discord/callback")
def discord_callback():
    state = request.args.get("state")
    code_param = request.args.get("code")

    if not state or not verify_state(state):
        return "Invalid or expired state", 400
    if not code_param:
        return "Discord auth failed", 400

    token = discord_exchange_token(code_param, DISCORD_REDIRECT)
    if "access_token" not in token:
        return "Discord auth failed", 400

    user = discord_get_user(token["access_token"])
    discord_id = str(user.get("id", "")) or ""
    if not discord_id:
        return "Discord user not found", 400

    # Optional: assign role automatically (best effort)
    try:
        discord_add_role(discord_id)
    except Exception:
        pass

    # Set a lightweight session for /portal/me (cookie tied to verifier domain)
    session["user"] = {
        "id": discord_id,
        "username": user.get("username", ""),
        "discriminator": user.get("discriminator", ""),
        "ts": now(),
    }

    # Redirect back to the main site with the Discord ID as feedback
    # If your homepage is index.html, append the ID for your JS to show a popup.
    return redirect(f"{MAIN_SITE_URL}/index.html?discord_id={discord_id}")


# ------------------------------------------------------------------------------
# Status: combine role check with overrides
# ------------------------------------------------------------------------------
@app.route("/status/<discord_id>")
def status(discord_id):
    did = str(discord_id)

    # Overrides short-circuit to granted
    if global_override:
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "⚡ Global admin override active",
        }), 200

    if admin_overrides.get(did):
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "⚡ Admin override active",
        }), 200

    # Normal path: check member + role
    member = discord_get_member(did)
    if "roles" in member:
        has = discord_has_role(member)
        return jsonify({
            "ok": True,
            "role_granted": bool(has),
            "message": "Subscriber role verified." if has else "Subscriber role not found.",
        }), 200

    status_code = member.get("status_code", 404)
    return jsonify({
        "ok": False,
        "role_granted": False,
        "message": f"Member not found or error (HTTP {status_code}).",
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
        active = bool(admin_overrides.get(did))
        return jsonify({"ok": True, "user_override": active, "discord_id": did}), 200

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
        "users": list(admin_overrides.keys())
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
# Health
# ------------------------------------------------------------------------------
@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": now()}), 200


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)