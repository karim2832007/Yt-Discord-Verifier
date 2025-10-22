# app.py
"""
Fixed Flask verifier
- Session-based OAuth state to avoid state signature/TTL issues
- Properly encoded Discord authorize URL with prompt=consent to discourage native app handoff
- Ensures cookie/CORS settings align with backend origin (use SESSION_COOKIE_DOMAIN env)
- Endpoints: /login/discord, /login/discord/callback, /portal/me, /status/<id>,
  /generate_key, /validate_key/<id>/<key>, logout, overrides and admin helpers
- Single active unused key persisted to KEYS_FILE
Env:
  SECRET_KEY, BASE_URL, SESSION_COOKIE_DOMAIN, DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET, DISCORD_REDIRECT (optional), DISCORD_GUILD_ID,
  DISCORD_ROLE_ID, DISCORD_BOT_TOKEN, OWNER_ID, STORE_DIR, KEYS_FILE, PORT
"""
import os
import time
import secrets
import logging
import json
import re
from datetime import timedelta
from typing import Dict, Any
from urllib.parse import urlencode, quote_plus
import requests
from flask import Flask, redirect, request, session, jsonify, render_template_string, make_response
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)

# App
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=1)

# Config / urls
BASE_URL = os.environ.get("BASE_URL", "https://gaming-mods.com").rstrip("/")
IONOS_INDEX = f"{BASE_URL}/index.html"
IONOS_GAMES = f"{BASE_URL}/games.html"

# Cookie / CORS: ensure this matches the host that will receive the session cookie
# Recommended: set SESSION_COOKIE_DOMAIN to the parent domain of your backend host (e.g. ".onrender.com")
SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", "") or None
if SESSION_COOKIE_DOMAIN:
    app.config.update(
        SESSION_COOKIE_DOMAIN=SESSION_COOKIE_DOMAIN,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="None",
        PROPAGATE_EXCEPTIONS=True,
    )
else:
    app.config.update(PROPAGATE_EXCEPTIONS=True)

CORS(app, origins=[BASE_URL], supports_credentials=True)

# Discord / owner config
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT = os.environ.get("DISCORD_REDIRECT", "").strip()  # optional override
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
OWNER_ID = os.environ.get("OWNER_ID", "")

# Storage
STORE_DIR = os.environ.get("STORE_DIR", ".")
os.makedirs(STORE_DIR, exist_ok=True)
KEYS_FILE = os.path.join(STORE_DIR, os.environ.get("KEYS_FILE", "keys_store.json"))
STATE_FILE = os.path.join(STORE_DIR, os.environ.get("STATE_FILE", "override_state.json"))

global_override = False
admin_overrides: Dict[str, Dict[str, Any]] = {}
login_history = []

def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({"global_override": global_override, "admin_overrides": admin_overrides}, f)
    except Exception:
        logging.exception("save_state failed")

def load_state():
    global global_override, admin_overrides
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE) as f:
                data = json.load(f)
            global_override = data.get("global_override", False)
            admin_overrides = data.get("admin_overrides", {})
    except Exception:
        logging.exception("load_state failed")

def load_keys() -> Dict[str, Any]:
    try:
        if not os.path.exists(KEYS_FILE):
            save_keys({})
        with open(KEYS_FILE) as f:
            return json.load(f)
    except Exception:
        logging.exception("load_keys failed")
        return {}

def save_keys(store: Dict[str, Any]):
    try:
        with open(KEYS_FILE, "w") as f:
            json.dump(store, f)
    except Exception:
        logging.exception("save_keys failed")

load_state()

def now_ts() -> int:
    return int(time.time())

def is_valid_discord_id(did: str) -> bool:
    return bool(re.fullmatch(r"\d{1,24}", did or ""))

def require_owner() -> bool:
    user = session.get("user")
    return bool(user and str(user.get("id")) == str(OWNER_ID))

def _safe_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}

# Discord API helpers
def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    url = "https://discord.com/api/oauth2/token"
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    try:
        resp = requests.post(url, data=data, headers=headers, timeout=15)
        return _safe_json(resp) if resp.status_code == 200 else {"error": "token_error", "status": resp.status_code, "body": resp.text}
    except Exception as e:
        logging.exception("discord_exchange_token")
        return {"error": "network", "message": str(e)}

def discord_get_user(token: str) -> dict:
    try:
        resp = requests.get("https://discord.com/api/users/@me", headers={"Authorization": f"Bearer {token}"}, timeout=15)
        return _safe_json(resp) if resp.status_code == 200 else {"error": "user_error", "status": resp.status_code, "body": resp.text}
    except Exception as e:
        logging.exception("discord_get_user")
        return {"error": "network", "message": str(e)}

def discord_member(did: str) -> dict:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN:
        return {"status_code": 400, "error": "missing_guild_or_bot_token"}
    try:
        resp = requests.get(f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}", headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
        if resp.status_code == 200:
            return _safe_json(resp)
        return {"status_code": resp.status_code, "error": resp.text}
    except Exception as e:
        logging.exception("discord_member")
        return {"status_code": 500, "error": str(e)}

def discord_is_banned(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN:
        return False
    try:
        resp = requests.get(f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/bans/{did}", headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
        return resp.status_code == 200
    except Exception:
        logging.exception("discord_is_banned")
        return False

def discord_has_role(member: dict) -> bool:
    return str(DISCORD_ROLE_ID) in [str(r) for r in member.get("roles", [])]

def discord_add_role(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN or not DISCORD_ROLE_ID:
        return False
    try:
        resp = requests.put(f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}", headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
        return resp.status_code in (200, 204)
    except Exception:
        logging.exception("discord_add_role")
        return False

def discord_remove_role(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN or not DISCORD_ROLE_ID:
        return False
    try:
        resp = requests.delete(f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}", headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
        return resp.status_code in (200, 204)
    except Exception:
        logging.exception("discord_remove_role")
        return False

# Utility to build a properly encoded Discord authorize URL with prompt=consent
def build_discord_authorize_url(state: str) -> str:
    redirect_uri = DISCORD_REDIRECT or (request.url_root.rstrip("/") + "/login/discord/callback")
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "identify",
        "state": state,
        "prompt": "consent"   # encourage the web consent flow
    }
    return "https://discord.com/api/oauth2/authorize?" + urlencode(params, quote_via=quote_plus)

# Error handler
@app.errorhandler(Exception)
def handle_exception(e):
    logging.exception("Unhandled exception")
    return jsonify({"ok": False, "error": str(e)}), 500

# Static redirects
@app.route("/")
def index():
    return redirect(IONOS_INDEX)

@app.route("/games")
def games():
    return redirect(IONOS_GAMES)

# OAuth: session-based state (robust)
@app.route("/login/discord")
def login_discord():
    if not DISCORD_CLIENT_ID:
        return "Discord client ID not configured", 500
    state = secrets.token_urlsafe(24)
    session['oauth_state'] = state
    auth_url = build_discord_authorize_url(state)
    logging.info("Redirecting to Discord authorize URL: %s", auth_url)
    # redirect in same top-level tab to avoid deep-link handoff
    return redirect(auth_url)

@app.route("/login/discord/callback")
def login_callback():
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    saved = session.pop('oauth_state', None)
    logging.info("OAuth callback received state=%r saved=%r code_present=%s", state, saved, bool(code))
    if not state or not saved or not secrets.compare_digest(state, saved):
        logging.warning("Invalid or expired OAuth state")
        return "Invalid or expired state", 400
    if not code:
        return "Missing code", 400

    redirect_uri = DISCORD_REDIRECT or request.base_url
    token_resp = discord_exchange_token(code, redirect_uri)
    if token_resp.get("error"):
        logging.warning("Token exchange failed: %s", token_resp)
        return render_template_string("<h2>Login failed</h2><pre>{{body}}</pre><p><a href='{{home}}'>Return</a></p>", body=token_resp, home=BASE_URL), 400

    access_token = token_resp.get("access_token")
    if not access_token:
        logging.warning("No access token in response")
        return "Token exchange returned no access token", 400

    user_info = discord_get_user(access_token)
    did = str(user_info.get("id") or "")
    if not did or not is_valid_discord_id(did):
        logging.warning("discord_get_user failed: %s", user_info)
        return render_template_string("<h2>User lookup failed</h2><pre>{{body}}</pre><p><a href='{{home}}'>Return</a></p>", body=user_info, home=BASE_URL), 400

    banned = discord_is_banned(did)
    member_resp = discord_member(did)
    is_member = "roles" in member_resp
    has_role = bool(is_member and discord_has_role(member_resp))

    # set session and log it; response happens after session is set so Set-Cookie header is emitted
    session.permanent = True
    session["user"] = {"id": did, "username": user_info.get("username", ""), "discriminator": user_info.get("discriminator", ""), "ts": now_ts()}
    login_history.append(session["user"])
    logging.info("Session set for user %s", did)

    # optional admin override behavior
    try:
        if (global_override or admin_overrides.get(did)) and is_member:
            discord_add_role(did)
            has_role = True
    except Exception:
        logging.exception("role assignment on login failed")

    if banned:
        return render_template_string("<h2>Blocked</h2><p>Your account is banned from the server.</p><p><a href='{{home}}'>Return</a></p>", home=BASE_URL), 403
    if not is_member:
        return render_template_string("<h2>Join required</h2><p>Please join the Discord server and try again.</p><p><a href='{{home}}'>Return</a></p>", home=BASE_URL), 403
    if not has_role:
        return render_template_string("<h2>Role missing</h2><p>Membership verified but required role missing.</p><p><a href='{{home}}'>Continue</a></p>", home=BASE_URL), 200

    # Redirect back to main site; session cookie should be set by this response
    resp = make_response(redirect(BASE_URL))
    logging.info("Redirecting back to %s with session cookie", BASE_URL)
    return resp

# Session and status endpoints
@app.route("/portal/me")
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({"ok": True, "user": user}), 200

@app.route("/status/<did>")
def status(did):
    if not is_valid_discord_id(did):
        return jsonify({"ok": False, "role_granted": False, "message": "Invalid ID format"}), 400
    if global_override:
        return jsonify({"ok": True, "role_granted": True, "message": "GLOBAL OVERRIDE"}), 200
    if admin_overrides.get(did):
        return jsonify({"ok": True, "role_granted": True, "message": "ADMIN OVERRIDE"}), 200

    banned = discord_is_banned(did)
    member = discord_member(did)
    if banned:
        return jsonify({"ok": False, "role_granted": False, "message": "Banned from server"}), 403
    if "roles" in member:
        has = discord_has_role(member)
        return jsonify({"ok": True, "role_granted": has, "message": ("Role present" if has else "Role missing")}), 200
    return jsonify({"ok": False, "role_granted": False, "message": ("Not in server" if member.get("status_code") == 404 else f"Member lookup error ({member.get('status_code')})")}), 404

@app.route("/logout")
def logout():
    session.clear()
    return redirect(BASE_URL)

# Keys: single active key per user
def _make_key_value(did: str) -> str:
    rnd = secrets.token_hex(24).upper()
    return f"GMD-{did}-{rnd}"

@app.route("/generate_key", methods=["POST"])
def generate_key():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    did = str(user.get("id") or "")
    if not is_valid_discord_id(did):
        return jsonify({"ok": False, "message": "Invalid user ID"}), 400

    member = discord_member(did)
    if "roles" not in member:
        return jsonify({"ok": False, "message": "Join the server before requesting a key"}), 403
    if not (discord_has_role(member) or global_override or admin_overrides.get(did)):
        return jsonify({"ok": False, "message": "Required role missing"}), 403

    store = load_keys()
    entry = store.get(did)
    if entry and not entry.get("used"):
        return jsonify({"ok": False, "message": "Active key already exists. Use it first."}), 409

    key_value = _make_key_value(did)
    store[did] = {"key": key_value, "used": False, "created_at": now_ts(), "used_at": None, "audit": [{"ts": now_ts(), "event": "issued"}]}
    save_keys(store)
    return jsonify({"ok": True, "key": key_value}), 200

@app.route("/validate_key/<did>/<key>", methods=["GET", "POST"])
def validate_key(did, key):
    did = str(did or "").strip()
    key = str(key or "").strip()
    def fail(status, msg):
        return jsonify({"ok": False, "valid": False, "message": msg}), status

    if not is_valid_discord_id(did):
        return fail(400, "Invalid ID format")
    if not key or not key.startswith(f"GMD-{did}-"):
        return fail(400, "Malformed key")

    try:
        if discord_is_banned(did):
            return fail(403, "Banned from server")
    except Exception:
        return fail(500, "Ban check failed")

    try:
        member = discord_member(did)
    except Exception:
        return fail(500, "Member lookup failed")

    if "roles" not in member:
        code = member.get("status_code")
        if code == 404:
            return fail(404, "Not in server")
        return fail(502, f"Member lookup error ({code})")

    has_role = False
    try:
        has_role = discord_has_role(member) or global_override or bool(admin_overrides.get(did))
    except Exception:
        has_role = False

    if not has_role:
        return fail(403, "Role missing")

    try:
        store = load_keys()
    except Exception:
        return fail(500, "Key store load failed")

    entry = store.get(did)
    if not entry:
        return fail(404, "No key issued for this user")
    if entry.get("used"):
        return fail(410, "Key already used")
    if str(entry.get("key")) != key:
        return fail(400, "Incorrect key")

    try:
        entry["used"] = True
        entry["used_at"] = now_ts()
        audit = entry.get("audit", [])
        audit.append({"ts": now_ts(), "event": "consumed"})
        entry["audit"] = audit
        store[did] = entry
        save_keys(store)
    except Exception:
        return fail(500, "Failed to consume key")

    return jsonify({"ok": True, "valid": True, "message": "Key valid and consumed"}), 200

# Admin / overrides (owner only)
@app.route("/override/all", methods=["GET", "POST", "DELETE"])
def override_all():
    global global_override
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    if request.method == "GET":
        return jsonify({"ok": True, "global_override": global_override}), 200
    if request.method == "POST":
        global_override = True; save_state(); return jsonify({"ok": True, "global_override": True}), 200
    if request.method == "DELETE":
        global_override = False; save_state(); return jsonify({"ok": True, "global_override": False}), 200
    return jsonify({"ok": False, "message": "Method not allowed"}), 405

@app.route("/override/<did>", methods=["GET", "POST", "DELETE"])
def override_user(did):
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    if request.method == "GET":
        return jsonify({"ok": True, "user_override": bool(admin_overrides.get(did)), "discord_id": did}), 200
    if request.method == "POST":
        admin_overrides[did] = {"username": "", "discriminator": ""}; save_state(); return jsonify({"ok": True, "user_override": True, "discord_id": did}), 200
    if request.method == "DELETE":
        admin_overrides.pop(did, None); save_state(); return jsonify({"ok": True, "user_override": False, "discord_id": did}), 200
    return jsonify({"ok": False, "message": "Method not allowed"}), 405

@app.route("/remove_role_now/<did>", methods=["POST"])
def remove_role_now(did):
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    success = discord_remove_role(did)
    return jsonify({"ok": success, "discord_id": did}), (200 if success else 500)

@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": now_ts()}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
