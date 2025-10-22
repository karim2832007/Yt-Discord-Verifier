# app.py
"""
Flask backend for verifier with server-side key issuance and validation.

Features:
- Discord OAuth (identify) with secure state signing
- Cross-site session cookies: static IONOS site can query /portal/me
- /status/<id> returns membership and role details; includes "not in server" and "banned" messages
- /generate_key (POST) issues a single active key per user; refuses if an unused key exists
- /validate_key/<id>/<key> validates key ownership, membership, role, and consumes the key
- Login callback shows clear pages if user is banned or not in the server

Env vars required:
SECRET_KEY, SESSION_COOKIE_DOMAIN, BASE_URL,
DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT,
DISCORD_GUILD_ID, DISCORD_ROLE_ID, DISCORD_BOT_TOKEN, OWNER_ID
"""
import os
import time
import secrets
import hmac
import hashlib
import base64
import logging
import json
import re
from datetime import timedelta
from typing import Dict, Any
import requests
from flask import (
    Flask, redirect, request, session, jsonify, render_template_string, url_for
)
from flask_cors import CORS
from dotenv import load_dotenv

# -----------------------------------------------------------------------------
# Load environment and configure app
# -----------------------------------------------------------------------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=1)

# Cookie config for cross-site usage (IONOS static site -> verifier)
SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", ".gaming-mods.com")
app.config.update(
    SESSION_COOKIE_DOMAIN=SESSION_COOKIE_DOMAIN,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",  # required to send cookies cross-site
    PROPAGATE_EXCEPTIONS=True,
)

# Base / static site URLs
BASE_URL = os.environ.get("BASE_URL", "https://gaming-mods.com").rstrip("/")
IONOS_INDEX = f"{BASE_URL}/index.html"
IONOS_GAMES = f"{BASE_URL}/games.html"
IONOS_DONATE = f"{BASE_URL}/donate.html"
IONOS_PRIVACY = f"{BASE_URL}/privacy.html"
IONOS_ADMIN = f"{BASE_URL}/admin.html"

# Allow the IONOS origin to call APIs with credentials
CORS(app, origins=[BASE_URL], supports_credentials=True)

# -----------------------------------------------------------------------------
# Discord & owner settings
# -----------------------------------------------------------------------------
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT = os.environ.get("DISCORD_REDIRECT", "").strip()
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
OWNER_ID = os.environ.get("OWNER_ID", "")

# -----------------------------------------------------------------------------
# State & overrides
# -----------------------------------------------------------------------------
STATE_FILE = "override_state.json"
KEYS_FILE = "keys_store.json"
global_override = False
admin_overrides: Dict[str, Dict[str, Any]] = {}
login_history = []
logging.basicConfig(level=logging.INFO)

def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({"global_override": global_override, "admin_overrides": admin_overrides}, f)
    except Exception:
        logging.exception("Failed to save override state")

def load_state():
    global global_override, admin_overrides
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE) as f:
                data = json.load(f)
            global_override = data.get("global_override", False)
            admin_overrides = data.get("admin_overrides", {})
    except Exception:
        logging.exception("Failed to load override state")

def load_keys() -> Dict[str, Any]:
    try:
        if os.path.exists(KEYS_FILE):
            with open(KEYS_FILE) as f:
                return json.load(f)
    except Exception:
        logging.exception("Failed to load keys store")
    return {}

def save_keys(store: Dict[str, Any]):
    try:
        with open(KEYS_FILE, "w") as f:
            json.dump(store, f)
    except Exception:
        logging.exception("Failed to save keys store")

load_state()

# -----------------------------------------------------------------------------
# Helpers: state signing, validation
# -----------------------------------------------------------------------------
STATE_TTL = 15 * 60  # seconds

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

def is_valid_discord_id(did: str) -> bool:
    return bool(re.fullmatch(r"\d{1,24}", did))

def require_owner() -> bool:
    user = session.get("user")
    return bool(user and str(user.get("id")) == str(OWNER_ID))

# -----------------------------------------------------------------------------
# Discord API helpers
# -----------------------------------------------------------------------------
def _safe_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}

def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    url = "https://discord.com/api/oauth2/token"
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": "GamingMods-Verifier/1.0 (+https://gaming-mods.com)",
    }

    MAX_ATTEMPTS = 4
    BACKOFF_BASE = 0.5
    MAX_SLEEP = 5

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = requests.post(url, data=data, headers=headers, timeout=15)
        except requests.RequestException as exc:
            logging.warning("Token exchange network error (attempt %d): %s", attempt, exc)
            if attempt == MAX_ATTEMPTS:
                return {"error": "network_error", "message": str(exc)}
            time.sleep(min(BACKOFF_BASE * (2 ** (attempt - 1)), MAX_SLEEP))
            continue

        if resp.status_code == 429:
            retry_after_hdr = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
            try:
                retry_after = int(retry_after_hdr) if retry_after_hdr else None
            except Exception:
                retry_after = None
            logging.warning("Token exchange 429 (attempt %d), retry_after=%s", attempt, retry_after)
            sleep_for = retry_after if (retry_after and retry_after > 0) else (BACKOFF_BASE * (2 ** (attempt - 1)))
            sleep_for = min(sleep_for, MAX_SLEEP)
            if attempt == MAX_ATTEMPTS:
                return {
                    "error": "rate_limited",
                    "status": 429,
                    "retry_after": retry_after,
                    "body": resp.text,
                    "json": _safe_json(resp),
                }
            time.sleep(sleep_for)
            continue

        if 500 <= resp.status_code < 600:
            logging.warning("Discord server error %s (attempt %d)", resp.status_code, attempt)
            if attempt == MAX_ATTEMPTS:
                return {
                    "error": "token_exchange_failed",
                    "status": resp.status_code,
                    "body": resp.text,
                    "json": _safe_json(resp),
                }
            time.sleep(min(BACKOFF_BASE * (2 ** (attempt - 1)), MAX_SLEEP))
            continue

        payload = _safe_json(resp)
        if resp.status_code != 200:
            logging.warning("Token exchange failed %s: %s", resp.status_code, resp.text)
            return {
                "error": "token_exchange_failed",
                "status": resp.status_code,
                "body": resp.text,
                "json": payload,
            }
        return payload

    return {"error": "token_exchange_failed", "status": "max_retries_exceeded"}

def discord_get_user(token: str) -> dict:
    try:
        resp = requests.get(
            "https://discord.com/api/users/@me",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "GamingMods-Verifier/1.0 (+https://gaming-mods.com)",
            },
            timeout=15,
        )
    except Exception as e:
        return {"error": "user_fetch_failed", "message": str(e)}
    data = _safe_json(resp)
    if resp.status_code != 200:
        return {"error": "user_fetch_failed", "status": resp.status_code, "body": resp.text, "json": data}
    return data

def discord_member(did: str) -> dict:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN:
        return {"status_code": 400, "error": "missing_guild_or_bot_token"}
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}"
    try:
        resp = requests.get(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
    except Exception as e:
        return {"status_code": 500, "error": str(e)}
    if resp.status_code == 200:
        return _safe_json(resp)
    return {"status_code": resp.status_code, "error": resp.text}

def discord_is_banned(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN:
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/bans/{did}"
    try:
        resp = requests.get(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
    except Exception:
        return False
    return resp.status_code == 200

def discord_has_role(member: dict) -> bool:
    return str(DISCORD_ROLE_ID) in [str(r) for r in member.get("roles", [])]

def discord_add_role(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN or not DISCORD_ROLE_ID:
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    resp = requests.put(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
    return resp.status_code in (200, 204)

def discord_remove_role(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN or not DISCORD_ROLE_ID:
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    resp = requests.delete(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
    return resp.status_code in (200, 204)

def should_assign_on_login(did: str) -> bool:
    return global_override or bool(admin_overrides.get(did, False))

# -----------------------------------------------------------------------------
# Error handler
# -----------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_exception(e):
    logging.exception("Unhandled exception:")
    return jsonify({"ok": False, "error": str(e)}), 500

# -----------------------------------------------------------------------------
# Front-end redirects (IONOS static site remains authoritative)
# -----------------------------------------------------------------------------
@app.route("/")
def serve_index():
    return redirect(IONOS_INDEX)

@app.route("/games")
def serve_games():
    return redirect(IONOS_GAMES)

@app.route("/privacy")
def serve_privacy():
    return redirect(IONOS_PRIVACY)

@app.route("/donate")
def serve_donate():
    return redirect(IONOS_DONATE)

@app.route("/admin")
def serve_admin():
    if not require_owner():
        return "Forbidden", 403
    return redirect(IONOS_ADMIN)

@app.route("/admin/logins")
def admin_logins():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    return jsonify({"ok": True, "logins": login_history}), 200

# -----------------------------------------------------------------------------
# OAuth endpoints
# -----------------------------------------------------------------------------
@app.route("/login/discord")
def login_discord():
    state = make_state()
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

    redirect_uri = DISCORD_REDIRECT or request.base_url
    token_resp = discord_exchange_token(code, redirect_uri)

    if isinstance(token_resp, dict) and token_resp.get("error") == "rate_limited":
        retry_after = token_resp.get("retry_after")
        body_preview = (token_resp.get("body") or "")[:1000]
        return render_template_string(
            "<!doctype html><html><head><meta charset=utf-8>"
            "<title>Discord rate limited</title></head><body>"
            "<h2>Discord rate limited</h2><p>Retry after: {{retry_after}}</p>"
            "<pre>{{body_preview}}</pre>"
            "<p><a href='{{home}}'>Return</a></p>"
            "</body></html>",
            retry_after=retry_after,
            body_preview=body_preview,
            home=IONOS_INDEX
        ), 429

    if isinstance(token_resp, dict) and token_resp.get("error"):
        brief = json.dumps({k: token_resp.get(k) for k in ("error", "status") if k in token_resp})
        body_preview = (token_resp.get("body") or "")[:800]
        return render_template_string(
            "<!doctype html><html><head><meta charset=utf-8>"
            "<title>Login error</title></head><body>"
            "<h2>Login failed</h2><pre>{{brief}}</pre><pre>{{body_preview}}</pre>"
            "<p><a href='{{home}}'>Return</a></p>"
            "</body></html>",
            brief=brief,
            body_preview=body_preview,
            home=IONOS_INDEX
        ), 400

    access_token = token_resp.get("access_token")
    if not access_token:
        logging.warning("Token response missing access_token: %s", token_resp)
        return jsonify({
            "ok": False,
            "message": "Token exchange succeeded but no access_token returned",
            "details": token_resp
        }), 400

    user_info = discord_get_user(access_token)
    did = str(user_info.get("id", "") or "")
    if not did or not is_valid_discord_id(did):
        logging.warning("discord_get_user failed: %s", user_info)
        return jsonify({"ok": False, "message": "Discord user lookup failed", "details": user_info}), 400

    # Determine membership and ban status for clear messaging
    banned = discord_is_banned(did)
    member_resp = discord_member(did)
    is_member = "roles" in member_resp
    has_role = bool(is_member and discord_has_role(member_resp))

    # Store session
    session.permanent = True
    session["user"] = {
        "id": did,
        "username": user_info.get("username", ""),
        "discriminator": user_info.get("discriminator", ""),
        "ts": now_ts()
    }
    login_history.append(session["user"])

    # Owner overrides: optionally add role on login
    try:
        if should_assign_on_login(did) and is_member:
            discord_add_role(did)
            has_role = True
    except Exception:
        logging.exception("Role assignment failed")

    # Present explicit messages for banned / not in server / missing role
    if banned:
        return render_template_string(
            "<!doctype html><html><head><meta charset=utf-8>"
            "<title>Access blocked</title></head><body>"
            "<h2>Your Discord account is banned from the server.</h2>"
            "<p>If you believe this is a mistake, contact the admins.</p>"
            "<p><a href='{{home}}'>Return</a></p>"
            "</body></html>",
            home=IONOS_INDEX
        ), 403

    if not is_member:
        return render_template_string(
            "<!doctype html><html><head><meta charset=utf-8>"
            "<title>Join required</title></head><body>"
            "<h2>You are not in the Discord server.</h2>"
            "<p>Please join and verify your membership, then try again.</p>"
            "<p><a href='{{home}}'>Return</a></p>"
            "</body></html>",
            home=IONOS_INDEX
        ), 403

    if not has_role:
        # Not fatal; they can still proceed to keys.html, but inform them here
        return render_template_string(
            "<!doctype html><html><head><meta charset=utf-8>"
            "<title>Role missing</title></head><body>"
            "<h2>Membership verified, but required role is missing.</h2>"
            "<p>If you just joined, wait a moment or contact admins.</p>"
            "<p><a href='{{home}}'>Continue</a></p>"
            "</body></html>",
            home=IONOS_INDEX
        ), 200

    # All good: redirect back home
    return redirect(IONOS_INDEX)

@app.route("/login/discord/callback")
def discord_callback_login():
    return _discord_callback()

@app.route("/discord/callback")
def discord_callback_plain():
    return _discord_callback()

# -----------------------------------------------------------------------------
# API: session info, logout, status
# -----------------------------------------------------------------------------
@app.route("/api/me")
def api_me():
    user = session.get("user")
    return jsonify({
        "logged_in": bool(user),
        "user_id": (user or {}).get("id"),
        "username": (user or {}).get("username"),
    }), 200

@app.route("/portal/me")
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({"ok": True, "user": user}), 200

@app.route("/logout")
def logout():
    session.clear()
    return redirect(IONOS_INDEX)

@app.route("/status/<did>")
def status(did):
    if not is_valid_discord_id(did):
        return jsonify({"ok": False, "role_granted": False, "message": "Invalid ID format"}), 400

    if global_override:
        return jsonify({"ok": True, "role_granted": True, "message": "GLOBAL OVERRIDE ACTIVE"}), 200
    if admin_overrides.get(did):
        return jsonify({"ok": True, "role_granted": True, "message": "ADMIN OVERRIDE"}), 200

    # Check ban and membership explicitly
    banned = discord_is_banned(did)
    member = discord_member(did)

    if banned:
        return jsonify({"ok": False, "role_granted": False, "message": "Banned from server"}), 403

    if "roles" in member:
        has = discord_has_role(member)
        return jsonify({"ok": True, "role_granted": has, "message": ("Role present" if has else "Role missing")}), 200

    return jsonify({
        "ok": False, "role_granted": False,
        "message": ("Not in server" if member.get("status_code") == 404 else f"Member lookup error (status {member.get('status_code')})")
    }), 404

@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": now_ts()}), 200

# -----------------------------------------------------------------------------
# Server-side keys: issue and validate
# -----------------------------------------------------------------------------
def _make_key_value(did: str) -> str:
    rnd = secrets.token_hex(24).upper()
    return f"GMD-{did}-{rnd}"

@app.route("/generate_key", methods=["POST"])
def generate_key():
    """
    Issues a single active key per user.
    Requires: logged-in session. Optionally validate role before issuing.
    Refuses if an unused key already exists.
    """
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    did = str(user.get("id") or "")
    if not is_valid_discord_id(did):
        return jsonify({"ok": False, "message": "Invalid user ID"}), 400

    # Optional: enforce role before issuance
    member = discord_member(did)
    if "roles" not in member:
        return jsonify({"ok": False, "message": "Join the server before requesting a key"}), 403
    if not discord_has_role(member) and not (global_override or admin_overrides.get(did)):
        return jsonify({"ok": False, "message": "Required role missing"}), 403

    store = load_keys()
    entry = store.get(did)

    if entry and not entry.get("used"):
        # One active key rule
        return jsonify({"ok": False, "message": "Active key already exists. Use or consume it first."}), 409

    # Issue new key
    key_value = _make_key_value(did)
    store[did] = {
        "key": key_value,
        "used": False,
        "created_at": now_ts(),
        "used_at": None,
        "audit": [{"ts": now_ts(), "event": "issued"}],
    }
    save_keys(store)
    return jsonify({"ok": True, "key": key_value}), 200

@app.route("/validate_key/<did>/<key>", methods=["GET", "POST"])
def validate_key(did, key):
    """
    Validates and consumes a key:
    - User must be in server and have role (or override)
    - Key must match the stored active key and be unused
    Returns { ok, valid, message } and consumes on success.
    """
    did = str(did or "")
    if not is_valid_discord_id(did):
        return jsonify({"ok": False, "valid": False, "message": "Invalid ID format"}), 400

    # Check ban/membership/role
    banned = discord_is_banned(did)
    if banned:
        return jsonify({"ok": False, "valid": False, "message": "Banned from server"}), 403

    member = discord_member(did)
    if "roles" not in member:
        return jsonify({"ok": False, "valid": False, "message": "Not in server"}), 404

    has_role = discord_has_role(member) or global_override or bool(admin_overrides.get(did))
    if not has_role:
        return jsonify({"ok": False, "valid": False, "message": "Role missing"}), 403

    # Validate key
    store = load_keys()
    entry = store.get(did)
    if not entry:
        return jsonify({"ok": False, "valid": False, "message": "No key issued for this user"}), 404

    if entry.get("used"):
        return jsonify({"ok": False, "valid": False, "message": "Key already used"}), 410

    if str(entry.get("key")) != str(key):
        return jsonify({"ok": False, "valid": False, "message": "Incorrect key"}), 400

    # Consume key
    entry["used"] = True
    entry["used_at"] = now_ts()
    audit = entry.get("audit", [])
    audit.append({"ts": now_ts(), "event": "consumed"})
    entry["audit"] = audit
    store[did] = entry
    save_keys(store)

    return jsonify({"ok": True, "valid": True, "message": "Key valid and consumed"}), 200

# -----------------------------------------------------------------------------
# Owner-only overrides and role removal endpoints
# -----------------------------------------------------------------------------
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
    users = [{"id": did, "username": info.get("username", ""), "discriminator": info.get("discriminator", "")}
             for did, info in admin_overrides.items()]
    return jsonify({
        "ok": True, "global_override": global_override, "users": users
    }), 200

@app.route("/remove_role_now/<did>", methods=["POST"])
def remove_role_now(did):
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    success = discord_remove_role(did)
    return jsonify({"ok": success, "discord_id": did}), (200 if success else 500)

@app.route("/remove_role_all", methods=["POST"])
def remove_role_all():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN:
        return jsonify({"ok": False, "message": "Missing guild or bot token"}), 400

    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        return jsonify({"ok": False, "message": "Failed to fetch members", "status": resp.status_code}), 500

    members = resp.json()
    removed, failed = [], []
    for m in members:
        did = str(m["user"]["id"])
        r = requests.delete(
            f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}",
            headers=headers, timeout=15
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

# -----------------------------------------------------------------------------
# Run server
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
