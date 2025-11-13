# app.py — Full fixed replacement
import os
import time
import secrets
import logging
import json
import sqlite3
from datetime import timedelta
from typing import Optional, Dict, Any

import requests
from flask import (
    Flask, redirect, request, session, jsonify, render_template_string, url_for
)
from flask_cors import CORS
from dotenv import load_dotenv

# -----------------------------------------------------------------------------
# Config / app init
# -----------------------------------------------------------------------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=1)
LOOTLABS_API_BASE = os.environ.get("LOOTLABS_API_BASE", "https://creators.lootlabs.gg/api/public")
LOOTLABS_API_KEY = os.environ.get("LOOTLABS_API_KEY")

# Session cookie settings to allow cross-site usage when needed (change as needed)
app.config.update(
    SESSION_COOKIE_DOMAIN=os.environ.get("SESSION_COOKIE_DOMAIN", None),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
    PROPAGATE_EXCEPTIONS=True,
)

# CORS: allow your frontend origin(s)
FRONTEND_ORIGINS = os.environ.get("FRONTEND_ORIGINS", "https://gaming-mods.com").split(",")
CORS(app, origins=[o.strip() for o in FRONTEND_ORIGINS], supports_credentials=True)

# Simple persistent state (admin overrides, login history, global override) stored in JSON
STATE_FILE = os.environ.get("STATE_FILE", "state.json")
DB_PATH = os.environ.get("DB_PATH", "keys.db")

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT = os.environ.get("DISCORD_REDIRECT", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
IONOS_INDEX = os.environ.get("IONOS_INDEX", "https://gaming-mods.com")
UA = os.environ.get("UA", "Verifier/1.0")

# Logging
logging.basicConfig(level=logging.INFO)
app.logger = logging.getLogger("verifier")
app.logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Persistent state helpers
# -----------------------------------------------------------------------------
def load_state() -> dict:
    try:
        if not os.path.exists(STATE_FILE):
            return {"admin_overrides": {}, "login_history": [], "global_override": False}
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        app.logger.exception("Failed to load state; using defaults")
        return {"admin_overrides": {}, "login_history": [], "global_override": False}

def save_state(state: dict):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
    except Exception:
        app.logger.exception("Failed to save state")

_state = load_state()
admin_overrides: Dict[str, Any] = _state.get("admin_overrides", {})
login_history = _state.get("login_history", [])
global_override: bool = bool(_state.get("global_override", False))

def set_global_override(val: bool):
    global global_override
    global_override = bool(val)
    _state["global_override"] = global_override
    save_state(_state)

def set_user_override(did: str, info: Optional[dict]):
    if info:
        admin_overrides[did] = info
    else:
        admin_overrides.pop(did, None)
    _state["admin_overrides"] = admin_overrides
    save_state(_state)

def append_login_history(user: dict):
    login_history.append(user)
    # keep a reasonable max
    if len(login_history) > 500:
        del login_history[0:len(login_history)-500]
    _state["login_history"] = login_history
    save_state(_state)

# -----------------------------------------------------------------------------
# SQLite: issued_keys table (single-use keys)
# -----------------------------------------------------------------------------
def init_db():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS issued_keys (
                    key TEXT PRIMARY KEY,
                    did TEXT,
                    expires_at REAL NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.commit()
    except Exception:
        app.logger.exception("Failed to init DB")

init_db()

def create_new_key(did: Optional[str]) -> str:
    with sqlite3.connect(DB_PATH) as conn:
        if did:
            conn.execute("DELETE FROM issued_keys WHERE did = ?", (did,))
        key = secrets.token_urlsafe(24)
        expires_at = time.time() + 24 * 60 * 60
        conn.execute(
            "INSERT INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
            (key, did, expires_at)
        )
        conn.commit()
    return key

def get_key_record(key: str) -> Optional[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT did, expires_at, used FROM issued_keys WHERE key = ?",
            (key,)
        ).fetchone()
        if row:
            return {"did": row[0], "expires_at": row[1], "used": row[2]}
    return None

def burn_key(key: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM issued_keys WHERE key = ?", (key,))
        conn.commit()

def list_keys() -> list:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT key, expires_at, did FROM issued_keys ORDER BY expires_at DESC").fetchall()
        return [{"key": r[0], "expires_at": r[1], "did": r[2]} for r in rows]

def purge_expired():
    with sqlite3.connect(DB_PATH) as conn:
        now = time.time()
        conn.execute("DELETE FROM issued_keys WHERE expires_at < ?", (now,))
        conn.commit()
        
def create_custom_key(custom_key: str, did: Optional[str], duration_seconds: int) -> str:
    """Create a custom key with arbitrary string and custom expiry."""
    with sqlite3.connect(DB_PATH) as conn:
        # Remove old keys for same user if needed
        if did:
            conn.execute("DELETE FROM issued_keys WHERE did = ?", (did,))
        expires_at = time.time() + duration_seconds
        conn.execute(
            "INSERT INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
            (custom_key, did, expires_at)
        )
        conn.commit()
    return custom_key

# -----------------------------------------------------------------------------
# Helper: owner check (requires session user and environment OWNER_ID)
# -----------------------------------------------------------------------------
def require_owner() -> bool:
    owner = os.environ.get("OWNER_ID")
    user = session.get("user")
    if not user or not owner:
        return False
    return str(user.get("id")) == str(owner)

def list_keys_for_did(did: str) -> list:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT key, expires_at FROM issued_keys WHERE did = ? ORDER BY expires_at DESC",
            (did,)
        ).fetchall()
        return [{"key": r[0], "expires_at": r[1]} for r in rows]


# -----------------------------------------------------------------------------
# Discord helpers: token exchange, user, guild member, role operations
# -----------------------------------------------------------------------------
def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    """
    Exchange code -> token. Returns dict:
      - success: parsed JSON token response (contains access_token)
      - error: {error:'rate_limited', retry_after:N, body:raw} on 429
      - other error: {error:'other', status:code, body:raw}
    """
    token_url = "https://discord.com/api/oauth2/token"
    headers = {"User-Agent": UA}
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri
    }
    try:
        r = requests.post(token_url, data=data, headers=headers, timeout=10)
        raw = r.text
        if r.status_code == 429:
            # handle rate limit
            try:
                js = r.json()
                retry_after = js.get("retry_after")
            except Exception:
                retry_after = None
            return {"error": "rate_limited", "retry_after": retry_after, "body": raw}
        if r.status_code != 200:
            return {"error": "other", "status": r.status_code, "body": raw}
        return r.json()
    except Exception as e:
        app.logger.exception("Token exchange failed")
        return {"error": "other", "status": 0, "body": str(e)}

def discord_get_user(access_token: str) -> dict:
    url = "https://discord.com/api/users/@me"
    headers = {"Authorization": f"Bearer {access_token}", "User-Agent": UA}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 429:
            try: js = r.json(); retry_after = js.get("retry_after")
            except Exception: retry_after = None
            return {"error": "rate_limited", "retry_after": retry_after, "body": r.text}
        if r.status_code != 200:
            return {"error": "other", "status": r.status_code, "body": r.text}
        return r.json()
    except Exception as e:
        app.logger.exception("discord_get_user failed")
        return {"error": "other", "status": 0, "body": str(e)}

def discord_member(did: str) -> dict:
    """Return discord member object or error wrapper."""
    if not DISCORD_BOT_TOKEN or not DISCORD_GUILD_ID:
        return {"error": "missing_config", "status_code": 0}
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            return {"status_code": r.status_code, "body": r.text}
        return r.json()
    except Exception:
        app.logger.exception("discord_member failed")
        return {"status_code": 0, "body": "exception"}

def discord_add_role(did: str) -> bool:
    if not DISCORD_BOT_TOKEN or not DISCORD_GUILD_ID or not DISCORD_ROLE_ID:
        app.logger.warning("Missing Discord bot config for role add")
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}
    try:
        r = requests.put(url, headers=headers, timeout=10)
        return r.status_code in (204, 200)
    except Exception:
        app.logger.exception("discord_add_role failed")
        return False

def discord_remove_role(did: str) -> bool:
    if not DISCORD_BOT_TOKEN or not DISCORD_GUILD_ID or not DISCORD_ROLE_ID:
        app.logger.warning("Missing Discord bot config for role remove")
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}
    try:
        r = requests.delete(url, headers=headers, timeout=15)
        return r.status_code in (200, 204)
    except Exception:
        app.logger.exception("discord_remove_role failed")
        return False

# -----------------------------------------------------------------------------
# Utilities and small pages used by the flow (error pages)
# -----------------------------------------------------------------------------
def login_error_page(title, brief, body_preview, home) -> Any:
    tpl = f"""
    <html><body style="font-family:system-ui,Segoe UI,Roboto,Arial">
      <h1>{title}</h1>
      <pre>{brief}</pre>
      <pre>{body_preview}</pre>
      <p><a href="{home}">Return</a></p>
    </body></html>
    """
    return render_template_string(tpl), 400

def rate_limit_page(retry_after, body_preview, retry_link, home) -> Any:
    tpl = f"""
    <html><body style="font-family:system-ui,Segoe UI,Roboto,Arial">
      <h1>Discord rate limit</h1>
      <p>Retry after: {retry_after}</p>
      <pre>{body_preview}</pre>
      <p><a href="{home}">Return</a></p>
      <p><a href="{retry_link}">Retry link</a></p>
    </body></html>
    """
    return render_template_string(tpl), 429

# -----------------------------------------------------------------------------
# Simple CSRF-like state for OAuth
# -----------------------------------------------------------------------------
def make_state() -> str:
    s = secrets.token_urlsafe(16)
    session.setdefault("_oauth_states", []).append({"s": s, "ts": time.time()})
    # trim old
    session["_oauth_states"] = [x for x in session["_oauth_states"] if x.get("ts", 0) > time.time() - 600]
    session.modified = True
    return s

def verify_state(s: str) -> bool:
    states = session.get("_oauth_states", [])
    for entry in list(states):
        if entry.get("s") == s:
            states.remove(entry)
            session["_oauth_states"] = states
            session.modified = True
            return True
    return False

# -----------------------------------------------------------------------------
# Routes: Portal / Login / Logout / Status / Health
# -----------------------------------------------------------------------------
@app.route("/portal/me")
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({"ok": True, "user": user}), 200
    
@app.route("/me", methods=["GET"])
def me():
    user = session.get("user") or {}
    return jsonify({
        "username": user.get("username"),
        "id": user.get("id"),
        # let the frontend know whether this session is owner/admin
        "is_admin": bool(is_owner_session())
    }), 200

@app.route("/logout")
def logout():
    session.clear()
    return redirect(IONOS_INDEX)

@app.route("/status/<did>")
def status(did):
    try:
        # Global override
        if global_override:
            return jsonify({
                "ok": True,
                "member": True,
                "role_granted": True,
                "username": "GLOBAL_OVERRIDE",
                "message": "GLOBAL OVERRIDE ACTIVE"
            }), 200

        # Admin override
        if admin_overrides.get(did):
            return jsonify({
                "ok": True,
                "member": True,
                "role_granted": True,
                "username": "ADMIN_OVERRIDE",
                "message": "ADMIN OVERRIDE"
            }), 200

        # Normal member lookup
        member = discord_member(did)
        if "user" in member:
            username = member.get("user", {}).get("username", "")
            return jsonify({
                "ok": True,
                "member": True,
                "role_granted": True,
                "username": username,
                "message": f"Welcome {username}! Don’t forget to get your key from the website."
            }), 200

        return jsonify({
            "ok": False,
            "member": False,
            "role_granted": False,
            "message": f"Member lookup error (status {member.get('status_code')})"
        }), 404
    except Exception:
        app.logger.exception("Error in /status")
        return jsonify({"ok": False, "message": "internal error"}), 500

@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": int(time.time())}), 200

# Add a safe root route to avoid unexpected 404 -> 500
@app.route("/")
def index_redirect():
    return redirect(IONOS_INDEX)

# -----------------------------------------------------------------------------
# Discord OAuth login + callback
# -----------------------------------------------------------------------------
@app.route("/login/discord")
def login_discord():
    state = make_state()
    redirect_uri = DISCORD_REDIRECT or f"{request.url_root.rstrip('/')}/login/discord/callback"
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        "&response_type=code&scope=identify"
        f"&state={state}"
    )
    return redirect(auth_url)

def _discord_callback():
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    if not state or not verify_state(state):
        return login_error_page("Invalid or expired state", "state invalid", "", IONOS_INDEX)
    if not code:
        return login_error_page("Missing OAuth code", "code missing", "", IONOS_INDEX)

    redirect_uri = DISCORD_REDIRECT or request.base_url
    token_resp = discord_exchange_token(code, redirect_uri)

    if isinstance(token_resp, dict) and token_resp.get("error") == "rate_limited":
        retry_after = token_resp.get("retry_after", None)
        body_preview = (token_resp.get("body") or "")[:800]
        retry_link = request.base_url + "?" + request.query_string.decode()
        return rate_limit_page(retry_after, body_preview, retry_link, IONOS_INDEX)

    if isinstance(token_resp, dict) and token_resp.get("error"):
        brief = json.dumps({k: token_resp.get(k) for k in ("error", "status") if k in token_resp})
        body_preview = (token_resp.get("body") or "")[:800]
        return login_error_page("Login failed", brief, body_preview, IONOS_INDEX)

    access_token = token_resp.get("access_token")
    if not access_token:
        return login_error_page("Login failed", "no access_token", json.dumps(token_resp)[:800], IONOS_INDEX)

    user_info = discord_get_user(access_token)
    if isinstance(user_info, dict) and user_info.get("error") == "rate_limited":
        retry_after = user_info.get("retry_after", None)
        body_preview = (user_info.get("body") or "")[:800]
        retry_link = request.base_url + "?" + request.query_string.decode()
        return rate_limit_page(retry_after, body_preview, retry_link, IONOS_INDEX)

    did = str(user_info.get("id") or "")
    if not did:
        return login_error_page("Discord user lookup failed", json.dumps(user_info)[:200], (user_info.get("body") or "")[:800], IONOS_INDEX)

    try:
        if global_override or bool(admin_overrides.get(did, False)):
            discord_add_role(did)
    except Exception:
        app.logger.exception("Role assignment failed")

    session.permanent = True
    session["user"] = {
        "id": did,
        "username": user_info.get("username", ""),
        "discriminator": user_info.get("discriminator", ""),
        "ts": int(time.time())
    }
    session.modified = True

    try:
        append_login_history(session["user"])
    except Exception:
        app.logger.exception("Failed to append login history")

    return redirect(f"{IONOS_INDEX}?discord_id={did}", code=302)

@app.route("/login/discord/callback")
def discord_callback_login():
    return _discord_callback()

@app.route("/discord/callback")
def discord_callback_plain():
    return _discord_callback()

from flask import Flask, request, jsonify, redirect
from urllib.parse import unquote_plus
import time

# -------------------------------------------------------------------
# Generate a new key (allow GET for LootLabs redirect + POST for UI)
# -------------------------------------------------------------------
@app.route("/generate_key", methods=["GET", "POST"])
def generate_key_route():
    try:
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not logged in"}), 401

        did = str(user.get("id")) if user.get("id") else None
        username = user.get("username", "")

        # Create a new key valid for 24h
        new_key = create_new_key(did)

        # If coming from LootLabs redirect, send user to external keys.html
        ref = request.referrer or ""
        if "loot-link.com" in ref:
            return redirect("https://gaming-mods.com/keys.html")

        # Otherwise return JSON (for frontend button/API use)
        return jsonify({
            "ok": True,
            "key": new_key,
            "expires_at": time.time() + 24*60*60,
            "message": f"Welcome {username}, here’s your new key."
        }), 200

    except Exception:
        app.logger.exception("Key generation failed")
        return jsonify({"ok": False, "message": "server error"}), 500


# -------------------------------------------------------------------
# List all keys for the logged-in user
# -------------------------------------------------------------------
@app.route("/keys", methods=["GET"])
def keys():
    # preserve original permission model (owner/admin)
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    try:
        with _conn() as conn:
            cur = conn.execute("SELECT key, did, expires_at, used, note FROM issued_keys ORDER BY expires_at DESC LIMIT 2000")
            rows = cur.fetchall()
        keys = [{"key": r[0], "did": r[1], "expires_at": int(r[2]) if r[2] else None, "used": r[3], "note": r[4]} for r in rows]
        return jsonify({"keys": keys}), 200
    except sqlite3.OperationalError as e:
        # Likely DB missing/table/schema problem
        current_app.logger.exception("keys list OperationalError")
        return jsonify({"ok": False, "message": "database error", "detail": str(e)}), 500
    except Exception as e:
        # Unexpected error: log full trace and return safe message
        current_app.logger.exception("keys list failed")
        return jsonify({"ok": False, "message": "server error", "detail": str(e)}), 500

@app.route("/revoke_key", methods=["POST"])
def revoke_key():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    if not key:
        return jsonify({"ok": False, "message": "no key provided"}), 400
    try:
        with _conn() as conn:
            conn.execute("DELETE FROM issued_keys WHERE key = ?", (key,))
            conn.commit()
        audit_log(session.get("user", {}).get("id"), "revoke_key", {"key": key})
        return jsonify({"ok": True}), 200
    except Exception:
        current_app.logger.exception("revoke_key failed")
        return jsonify({"ok": False, "message": "server error"}), 500



# -------------------------------------------------------------------
# Burn a key (admin only)
# -------------------------------------------------------------------
@app.route("/admin/key/<path:key>", methods=["DELETE"])
def admin_burn_key(key):
    try:
        if not require_owner():
            return jsonify({"ok": False, "message": "Forbidden"}), 403

        # Normalize key for safety
        key = unquote_plus(key).strip()
        burn_key(key)

        return jsonify({
            "ok": True,
            "deleted": key,
            "message": f"Key {key} has been burned."
        }), 200

    except Exception:
        app.logger.exception("Failed to burn key")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/generate_custom_key", methods=["POST"])
def generate_custom_key():
    # keep your original auth behavior (here we require logged-in user; adjust as needed)
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401

    data = request.get_json(silent=True) or {}
    # frontend sends duration in hours; convert to seconds server-side
    # but also accept duration already in seconds if 'seconds' field used
    hours = data.get("duration_hours")
    duration_seconds = None
    if hours is not None:
        try:
            duration_seconds = int(hours) * 3600
        except Exception:
            return jsonify({"ok": False, "message": "invalid duration_hours"}), 400
    else:
        # fallback to legacy 'duration' field (seconds)
        duration_seconds = int(data.get("duration", 86400))

    custom_key = data.get("key")
    did = data.get("did") or None
    note = data.get("note") or ""

    if not custom_key or len(str(custom_key)) < 3:
        return jsonify({"ok": False, "message": "key too short"}), 400

    if did:
        if not str(did).isdigit() or not (16 <= len(str(did)) <= 21):
            return jsonify({"ok": False, "message": "invalid discord id"}), 400

    expires_at = int(time.time()) + int(duration_seconds)

    try:
        with _conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO issued_keys (key, did, expires_at, used, note) VALUES (?, ?, ?, 0, ?)",
                (custom_key, did, expires_at, note)
            )
            conn.commit()
        # audit the creation (actor id from session)
        audit_log(user.get("id"), "generate_custom_key", {"key": custom_key, "did": did, "expires_at": expires_at})
        return jsonify({"ok": True, "key": custom_key, "expires_at": expires_at}), 200
    except Exception:
        current_app.logger.exception("generate_custom_key failed")
        return jsonify({"ok": False, "message": "server error"}), 500


# -------------------------------------------------------------------
# Validate a key (fix Android encoding issues)
# -------------------------------------------------------------------
@app.route("/validate_key/<path:key>", methods=["GET"])
@app.route("/validate_key", methods=["POST"])
def validate_key():
    # If your old route was public for games, keep it public: no admin guard here
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    if not key:
        return jsonify({"ok": False, "message": "no key provided"}), 400

    now = int(time.time())

    # check global override first
    try:
        global_row = None
        with _conn() as conn:
            cur = conn.execute("SELECT expires_at FROM overrides WHERE id = 'GLOBAL'")
            global_row = cur.fetchone()
        if global_row and global_row[0] and int(global_row[0]) > now:
            global_expires = int(global_row[0])
            remaining = max(0, global_expires - now)
            return jsonify({
                "ok": True,
                "reason": "global override active",
                "expires_at": global_expires,
                "remaining_seconds": remaining,
                "legacy_remaining_seconds": min(remaining, LEGACY_LIMIT_SECONDS),
                "legacy_duration": LEGACY_LIMIT_SECONDS
            }), 200
    except Exception:
        current_app.logger.exception("validate_key global check error")

    rec = fetch_key_record(key)
    if not rec:
        return jsonify({"ok": False, "message": "not found"}), 404

    expires_at = rec.get("expires_at") or 0
    remaining = max(0, int(expires_at - now)) if expires_at else 0

    if expires_at and expires_at < now:
        return jsonify({
            "ok": False,
            "message": "expired",
            "key": rec["key"],
            "did": rec["did"],
            "expires_at": expires_at,
            "remaining_seconds": 0,
            "legacy_remaining_seconds": 0,
            "legacy_duration": LEGACY_LIMIT_SECONDS
        }), 200

    return jsonify({
        "ok": True,
        "key": rec["key"],
        "did": rec["did"],
        "expires_at": expires_at,
        "remaining_seconds": remaining,
        "legacy_remaining_seconds": min(remaining, LEGACY_LIMIT_SECONDS),
        "legacy_duration": LEGACY_LIMIT_SECONDS
    }), 200


# -------------------------------------------------------------------
# Admin logins listing
# -------------------------------------------------------------------
@app.route("/admin/logins", methods=["GET"])
def admin_logins():
    try:
        if not require_owner():
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        return jsonify({"ok": True, "logins": login_history}), 200
    except Exception:
        app.logger.exception("Failed to fetch admin logins")
        return jsonify({"ok": False, "message": "server error"}), 500


# -------------------------------------------------------------------
# Overrides (owner only)
# -------------------------------------------------------------------
@app.route("/override/all", methods=["GET", "POST", "DELETE"])
def override_all():
    try:
        global global_override
        if not require_owner():
            return jsonify({"ok": False, "message": "Forbidden"}), 403

        if request.method == "GET":
            return jsonify({"ok": True, "global_override": bool(global_override)}), 200
        if request.method == "POST":
            set_global_override(True)
            return jsonify({"ok": True, "global_override": True}), 200
        if request.method == "DELETE":
            set_global_override(False)
            return jsonify({"ok": True, "global_override": False}), 200

        return jsonify({"ok": False, "message": "Method not allowed"}), 405

    except Exception:
        app.logger.exception("override_all failed")
        return jsonify({"ok": False, "message": "server error"}), 500


@app.route("/override/<did>", methods=["GET", "POST", "DELETE"])
def override_user(did):
    try:
        if not require_owner():
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        if request.method == "GET":
            return jsonify({"ok": True, "user_override": bool(admin_overrides.get(did)), "discord_id": did}), 200
        if request.method == "POST":
            set_user_override(did, {"username": "", "discriminator": ""})
            return jsonify({"ok": True, "user_override": True, "discord_id": did}), 200
        if request.method == "DELETE":
            set_user_override(did, None)
            return jsonify({"ok": True, "user_override": False, "discord_id": did}), 200
        return jsonify({"ok": False, "message": "Method not allowed"}), 405
    except Exception:
        app.logger.exception("override_user failed")
        return jsonify({"ok": False, "message": "server error"}), 500

# -----------------------------------------------------------------------------
# Role removal (owner only)
# -----------------------------------------------------------------------------
@app.route("/remove_role_now/<did>", methods=["POST"])
def remove_role_now(did):
    try:
        if not require_owner():
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        success = discord_remove_role(did)
        return jsonify({"ok": success, "discord_id": did}), (200 if success else 500)
    except Exception:
        app.logger.exception("remove_role_now failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/remove_role_all", methods=["POST"])
def remove_role_all():
    try:
        if not require_owner():
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN or not DISCORD_ROLE_ID:
            return jsonify({"ok": False, "message": "Missing guild or bot token"}), 400
        url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000"
        headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            return jsonify({"ok": False, "message": "Failed to fetch members", "status": r.status_code}), 500
        members = r.json()
        removed, failed = [], []
        for m in members:
            try:
                did = str(m["user"]["id"])
                r2 = requests.delete(
                    f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}",
                    headers=headers, timeout=10
                )
                if r2.status_code in (200, 204):
                    removed.append(did)
                else:
                    failed.append(did)
            except Exception:
                app.logger.exception("Error removing role")
                failed.append(did)
        return jsonify({
            "ok": True,
            "removed_count": len(removed),
            "failed_count": len(failed),
            "removed_sample": removed[:10],
            "failed_sample": failed[:10]
        }), 200
    except Exception:
        app.logger.exception("remove_role_all failed")
        return jsonify({"ok": False, "message": "server error"}), 500

# -----------------------------------------------------------------------------
# Misc: purge expired keys
# -----------------------------------------------------------------------------
@app.route("/admin/keys/purge", methods=["POST"])
def purge_keys():
    try:
        if not require_owner():
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        purge_expired()
        return jsonify({"ok": True}), 200
    except Exception:
        app.logger.exception("purge_keys failed")
        return jsonify({"ok": False, "message": "server error"}), 500

from flask import jsonify

# Debug: confirm env vars are loaded
@app.route("/debug/env")
def debug_env():
    return jsonify({
        "base": LOOTLABS_API_BASE,
        "key_loaded": bool(LOOTLABS_API_KEY)  # don’t print the key itself
    })

# Test: call LootLabs API with your key
@app.route("/debug/lootlabs")
def debug_lootlabs():
    url = f"{LOOTLABS_API_BASE}/content_locker"
    headers = {
        "Authorization": f"Bearer {LOOTLABS_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "title": "Debug Locker",
        "url": "https://gaming-mods.com",
        "tier_id": 1,
        "number_of_tasks": 1
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=10)
        return jsonify({
            "status": r.status_code,
            "body": r.json() if r.headers.get("content-type","").startswith("application/json") else r.text
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
import os, sqlite3, time, json
from flask import request, jsonify, session, current_app

DB_PATH = globals().get("DB_PATH", os.environ.get("ADIME_DB_PATH", "data.db"))
OWNER_ID = os.environ.get("OWNER_ID")
LEGACY_LIMIT_SECONDS = 86400

def _conn():
    return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)

def is_owner_session():
    user = session.get("user")
    if not user:
        return False
    if user.get("is_admin"):
        return True
    if OWNER_ID and str(user.get("id")) == str(OWNER_ID):
        return True
    return False

def audit_log(actor_id, action, meta=None):
    try:
        with _conn() as conn:
            conn.execute(
                "INSERT INTO admin_audit (ts, actor_id, action, meta) VALUES (?, ?, ?, ?)",
                (int(time.time()), str(actor_id) if actor_id else None, action, json.dumps(meta) if meta else None)
            )
            conn.commit()
    except Exception:
        current_app.logger.exception("audit_log failed")

def get_active_global_override(now=None):
    now = now or int(time.time())
    try:
        with _conn() as conn:
            cur = conn.execute("SELECT expires_at FROM overrides WHERE id = 'GLOBAL'")
            r = cur.fetchone()
            if r and r[0] and int(r[0]) > now:
                return int(r[0])
    except Exception:
        current_app.logger.exception("get_active_global_override")
    return None

def fetch_key_record(key):
    try:
        with _conn() as conn:
            cur = conn.execute("SELECT key, did, expires_at, used, note FROM issued_keys WHERE key = ?", (key,))
            r = cur.fetchone()
        if not r:
            return None
        return {"key": r[0], "did": r[1], "expires_at": int(r[2]) if r[2] else None, "used": r[3], "note": r[4]}
    except Exception:
        current_app.logger.exception("fetch_key_record")
        return None
with _conn() as conn:
    conn.execute("""CREATE TABLE IF NOT EXISTS overrides (
                      id TEXT PRIMARY KEY,
                      expires_at INTEGER,
                      created_at INTEGER
                    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS admin_audit (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      ts INTEGER,
                      actor_id TEXT,
                      action TEXT,
                      meta TEXT
                    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS issued_keys (
                      key TEXT PRIMARY KEY,
                      did TEXT,
                      expires_at INTEGER,
                      used INTEGER DEFAULT 0,
                      note TEXT
                    )""")
    conn.commit()
@app.route("/create_override", methods=["POST"])
def create_override():
    # keep admin-only guard if your original route required admin; adapt to your auth
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    id_ = data.get("id")
    # frontend now sends hours for overrides too; convert to seconds
    hours = data.get("duration_hours")
    if hours is not None:
        try:
            duration_seconds = int(hours) * 3600
        except Exception:
            return jsonify({"ok": False, "message": "invalid duration_hours"}), 400
    else:
        duration_seconds = int(data.get("duration", 86400))
    if not id_:
        return jsonify({"ok": False, "message": "no id provided"}), 400
    if id_ != "GLOBAL":
        if not str(id_).isdigit() or not (16 <= len(str(id_)) <= 21):
            return jsonify({"ok": False, "message": "invalid discord id"}), 400
    expires_at = int(time.time()) + duration_seconds
    try:
        with _conn() as conn:
            conn.execute("INSERT OR REPLACE INTO overrides (id, expires_at, created_at) VALUES (?, ?, ?)",
                         (id_, expires_at, int(time.time())))
            conn.commit()
        audit_log(session.get("user", {}).get("id"), "create_override", {"id": id_, "expires_at": expires_at})
        return jsonify({"ok": True, "id": id_, "expires_at": expires_at}), 200
    except Exception:
        current_app.logger.exception("create_override failed")
        return jsonify({"ok": False, "message": "server error"}), 500
@app.route("/overrides", methods=["GET"])
def overrides():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    try:
        with _conn() as conn:
            cur = conn.execute("SELECT id, expires_at, created_at FROM overrides ORDER BY created_at DESC LIMIT 500")
            rows = cur.fetchall()
        overrides = [{"id": r[0], "expires_at": int(r[1]) if r[1] else None, "created_at": int(r[2]) if r[2] else None} for r in rows]
        return jsonify({"overrides": overrides}), 200
    except Exception:
        current_app.logger.exception("overrides list failed")
        return jsonify({"ok": False, "message": "server error"}), 500


# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
