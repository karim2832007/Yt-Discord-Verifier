#!/usr/bin/env python3
# app.py — Drop-in replacement for your verifier backend
# - Preserves all routes and behavior in your repo
# - Fixes duplicate-route issues, uses SQLite for persistence (keys + clicks)
# - Robust /start_step, /postback, /verify_click flow with race tolerance
# - Discord OAuth, key issuance, admin overrides, debug endpoints included
# - Environment-driven config, minimal external deps: flask, flask_cors, requests, python-dotenv

import os
import time
import secrets
import logging
import json
import sqlite3
from datetime import timedelta
from typing import Optional, Dict, Any, List
from urllib.parse import unquote_plus

import requests
from flask import (
    Flask, redirect, request, session, jsonify, render_template_string,
    url_for, send_from_directory, g
)
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

# ---------- Config ----------
APP_NAME = "verifier"
DB_PATH = os.environ.get("DB_PATH", "verifier.sqlite")
STATE_FILE = os.environ.get("STATE_FILE", "state.json")
FRONTEND_ORIGINS = os.environ.get("FRONTEND_ORIGINS", "https://gaming-mods.com").split(",")
FRONTEND_ORIGIN = FRONTEND_ORIGINS[0].strip()
LOOTLABS_API_BASE = os.environ.get("LOOTLABS_API_BASE", "https://creators.lootlabs.gg/api/public")
LOOTLABS_API_KEY = os.environ.get("LOOTLABS_API_KEY")
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT = os.environ.get("DISCORD_REDIRECT", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
IONOS_INDEX = os.environ.get("IONOS_INDEX", "https://gaming-mods.com")
UA = os.environ.get("UA", "Verifier/1.0")
OWNER_ID = os.environ.get("OWNER_ID")
LEGACY_LIMIT_SECONDS = 86400

# ---------- App init ----------
app = Flask(__name__, static_folder="static")
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(days=1)
app.config.update(
    SESSION_COOKIE_DOMAIN=os.environ.get("SESSION_COOKIE_DOMAIN", None),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
    PROPAGATE_EXCEPTIONS=True,
)
CORS(app, origins=[o.strip() for o in FRONTEND_ORIGINS], supports_credentials=True)
CORS(app, resources={r"/admin/api/*": {"origins": "https://gaming-mods.com"}})
# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(APP_NAME)

# ---------- Persistent state helpers (state.json) ----------
def load_state() -> dict:
    try:
        if not os.path.exists(STATE_FILE):
            return {"admin_overrides": {}, "login_history": [], "global_override": False}
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        logger.exception("load_state failed")
        return {"admin_overrides": {}, "login_history": [], "global_override": False}

def save_state(s: dict):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(s, fh, indent=2)
    except Exception:
        logger.exception("save_state failed")

_state = load_state()
admin_overrides: Dict[str, Any] = _state.get("admin_overrides", {})
login_history: List[Dict[str, Any]] = _state.get("login_history", [])
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
    if len(login_history) > 500:
        del login_history[0: len(login_history) - 500]
    _state["login_history"] = login_history
    save_state(_state)

# ---------- SQLite (keys + clicks) ----------
def _conn():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        with _conn() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS issued_keys (
              key TEXT PRIMARY KEY,
              did TEXT,
              expires_at REAL NOT NULL,
              used INTEGER NOT NULL DEFAULT 0
            );
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts INTEGER,
              actor_id TEXT,
              action TEXT,
              meta TEXT
            );
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS overrides (
              id TEXT PRIMARY KEY,
              expires_at INTEGER,
              created_at INTEGER
            );
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS clicks (
              token TEXT PRIMARY KEY,
              loot_click_id TEXT UNIQUE,
              session_id TEXT,
              step INTEGER,
              status TEXT,
              created_at INTEGER,
              confirmed_at INTEGER,
              used_at INTEGER,
              expires_at INTEGER
            );
            """)
            conn.commit()
    except Exception:
        logger.exception("init_db failed")

init_db()

# ---------- Key helpers ----------
def create_new_key(did: Optional[str]) -> str:
    with _conn() as conn:
        if did:
            conn.execute("DELETE FROM issued_keys WHERE did = ?", (did,))
        key = secrets.token_urlsafe(10)
        expires_at = time.time() + 24 * 60 * 60
        conn.execute("INSERT INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
                     (key, did, expires_at))
        conn.commit()
        return key

def create_custom_key(custom_key: str, did: Optional[str], duration_seconds: int) -> str:
    with _conn() as conn:
        if did:
            conn.execute("DELETE FROM issued_keys WHERE did = ?", (did,))
        expires_at = time.time() + duration_seconds
        conn.execute("INSERT OR REPLACE INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
                     (custom_key, did, expires_at))
        conn.commit()
        return custom_key

def get_key_record(key: str) -> Optional[dict]:
    with _conn() as conn:
        row = conn.execute("SELECT did, expires_at, used FROM issued_keys WHERE key = ?", (key,)).fetchone()
        if row:
            return {"did": row[0], "expires_at": row[1], "used": row[2]}
    return None

def burn_key(key: str):
    with _conn() as conn:
        conn.execute("DELETE FROM issued_keys WHERE key = ?", (key,))
        conn.commit()

def list_keys_for_did(did: str) -> list:
    with _conn() as conn:
        rows = conn.execute("SELECT key, expires_at FROM issued_keys WHERE did = ? ORDER BY expires_at DESC", (did,)).fetchall()
    return [{"key": r[0], "expires_at": r[1]} for r in rows]

def purge_expired():
    with _conn() as conn:
        now = time.time()
        conn.execute("DELETE FROM issued_keys WHERE expires_at < ?", (now,))
        conn.commit()

def set_override(id_: str, expires_at_ts: int):
    with _conn() as conn:
        conn.execute("INSERT OR REPLACE INTO overrides (id, expires_at, created_at) VALUES (?, ?, ?)",
                     (id_, int(expires_at_ts), int(time.time())))
        conn.commit()

def get_override(id_: str) -> Optional[Dict[str, Any]]:
    with _conn() as conn:
        cur = conn.execute("SELECT id, expires_at, created_at FROM overrides WHERE id = ?", (id_,))
        r = cur.fetchone()
        if not r:
            return None
        return {"id": r[0], "expires_at": int(r[1]) if r[1] else None, "created_at": int(r[2]) if r[2] else None}

def get_active_global_override(now: Optional[int] = None) -> Optional[int]:
    now = now or int(time.time())
    with _conn() as conn:
        cur = conn.execute("SELECT expires_at FROM overrides WHERE id = 'GLOBAL'")
        r = cur.fetchone()
        if r and r[0] and int(r[0]) > now:
            return int(r[0])
    return None

def audit_log(actor_id: Optional[str], action: str, meta: Optional[Dict] = None):
    try:
        with _conn() as conn:
            conn.execute("INSERT INTO admin_audit (ts, actor_id, action, meta) VALUES (?, ?, ?, ?)",
                         (int(time.time()), str(actor_id) if actor_id else None, action, json.dumps(meta) if meta else None))
            conn.commit()
    except Exception:
        logger.exception("audit_log failed")

# ---------- Discord helpers ----------
def discord_exchange_token(code: str, redirect_uri: str) -> dict:
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
        if r.status_code == 429:
            try:
                js = r.json(); retry_after = js.get("retry_after")
            except Exception:
                retry_after = None
            return {"error": "rate_limited", "retry_after": retry_after, "body": r.text}
        if r.status_code != 200:
            return {"error": "other", "status": r.status_code, "body": r.text}
        return r.json()
    except Exception as e:
        logger.exception("discord token exchange failed")
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
        logger.exception("discord_get_user failed")
        return {"error": "other", "status": 0, "body": str(e)}

def discord_member(did: str) -> dict:
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
        logger.exception("discord_member failed")
        return {"status_code": 0, "body": "exception"}

def discord_add_role(did: str) -> bool:
    if not DISCORD_BOT_TOKEN or not DISCORD_GUILD_ID or not DISCORD_ROLE_ID:
        logger.warning("Missing Discord bot config for role add")
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}
    try:
        r = requests.put(url, headers=headers, timeout=10)
        return r.status_code in (204, 200)
    except Exception:
        logger.exception("discord_add_role failed")
        return False

def discord_remove_role(did: str) -> bool:
    if not DISCORD_BOT_TOKEN or not DISCORD_GUILD_ID or not DISCORD_ROLE_ID:
        logger.warning("Missing Discord bot config for role remove")
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}
    try:
        r = requests.delete(url, headers=headers, timeout=15)
        return r.status_code in (200, 204)
    except Exception:
        logger.exception("discord_remove_role failed")
        return False

# ---------- Simple pages / helpers ----------
def login_error_page(title, brief, body_preview, home):
    tpl = f"""<html><body style="font-family:system-ui,Segoe UI,Roboto,Arial">
<h1>{title}</h1>
<pre>{brief}</pre>
<pre>{body_preview}</pre>
<p><a href="{home}">Return</a></p>
</body></html>"""
    return render_template_string(tpl), 400

def rate_limit_page(retry_after, body_preview, retry_link, home):
    tpl = f"""<html><body style="font-family:system-ui,Segoe UI,Roboto,Arial">
<h1>Discord rate limit</h1>
<p>Retry after: {retry_after}</p>
<pre>{body_preview}</pre>
<p><a href="{home}">Return</a></p>
<p><a href="{retry_link}">Retry link</a></p>
</body></html>"""
    return render_template_string(tpl), 429

# ---------- OAuth CSRF-like helpers ----------
def make_state() -> str:
    s = secrets.token_urlsafe(16)
    session.setdefault("_oauth_states", []).append({"s": s, "ts": time.time()})
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

# ---------- Clicks / loot mapping helpers (SQLite-backed) ----------
def _now(): return int(time.time())
def _gen(n=24): return secrets.token_urlsafe(n)

def insert_click(token, session_id, step, status="pending", click_id=None, ttl=3600):
    now = _now()
    expires = now + int(ttl)
    with _conn() as conn:
        conn.execute("""INSERT OR REPLACE INTO clicks
            (token, loot_click_id, session_id, step, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
                     (token, click_id, session_id, step, status, now, expires))
        conn.commit()

def find_click_by_token(token):
    if not token: return None
    with _conn() as conn:
        r = conn.execute("SELECT * FROM clicks WHERE token = ? LIMIT 1", (token,)).fetchone()
        return dict(r) if r else None

def find_click_by_clickid(click_id):
    if not click_id: return None
    with _conn() as conn:
        r = conn.execute("SELECT * FROM clicks WHERE loot_click_id = ? LIMIT 1", (click_id,)).fetchone()
        return dict(r) if r else None

def confirm_token(token, click_id):
    now = _now()
    with _conn() as conn:
        conn.execute("UPDATE clicks SET status='confirmed', loot_click_id=?, confirmed_at=? WHERE token=?",
                     (click_id, now, token))
        conn.commit()

def confirm_clickid(click_id):
    now = _now()
    with _conn() as conn:
        row = conn.execute("SELECT token FROM clicks WHERE loot_click_id = ? LIMIT 1", (click_id,)).fetchone()
        if row:
            token = row["token"]
            conn.execute("UPDATE clicks SET status='confirmed', confirmed_at=? WHERE token=?", (now, token))
            conn.commit()
            return token
    return None

def placeholder_for_clickid(click_id, step=None, ttl=3600):
    token = _gen(28)
    now = _now()
    expires = now + int(ttl)
    with _conn() as conn:
        conn.execute("""INSERT INTO clicks (token, loot_click_id, session_id, step, status, created_at, confirmed_at, expires_at)
                        VALUES (?, ?, ?, ?, 'confirmed', ?, ?, ?)""",
                     (token, click_id, None, step, now, now, expires))
        conn.commit()
    return token

def mark_used(token):
    now = _now()
    with _conn() as conn:
        conn.execute("UPDATE clicks SET status='used', used_at=? WHERE token=?", (now, token))
        conn.commit()

# ---------- Routes (preserve names) ----------
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
    try:
        if global_override:
            return jsonify({"ok": True, "member": True, "role_granted": True,
                            "username": "GLOBAL_OVERRIDE", "message": "GLOBAL OVERRIDE ACTIVE"}), 200
        if admin_overrides.get(did):
            return jsonify({"ok": True, "member": True, "role_granted": True,
                            "username": "ADMIN_OVERRIDE", "message": "ADMIN OVERRIDE"}), 200
        member = discord_member(did)
        if "user" in member:
            username = member.get("user", {}).get("username", "")
            return jsonify({"ok": True, "member": True, "role_granted": True,
                            "username": username,
                            "message": f"Welcome {username}! Don’t forget to get your key from the website."}), 200
        return jsonify({"ok": False, "member": False, "role_granted": False,
                        "message": f"Member lookup error (status {member.get('status_code')})"}), 404
    except Exception:
        logger.exception("Error in /status")
        return jsonify({"ok": False, "message": "internal error"}), 500

@app.route("/health", methods=["GET", "HEAD"])
def health():
    return jsonify({"ok": True, "ts": int(time.time())}), 200

@app.route("/")
def index_redirect():
    return redirect(IONOS_INDEX)

# ---------- OAuth ----------
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
        logger.exception("Role assignment failed")
    session.permanent = True
    session["user"] = {"id": did, "username": user_info.get("username", ""), "discriminator": user_info.get("discriminator", ""), "ts": int(time.time())}
    session.modified = True
    try:
        append_login_history(session["user"])
    except Exception:
        logger.exception("append_login_history failed")
    return redirect(f"{IONOS_INDEX}?discord_id={did}", code=302)

@app.route("/login/discord/callback")
def discord_callback_login():
    return _discord_callback()

@app.route("/discord/callback")
def discord_callback_plain():
    return _discord_callback()

# ---------- Key generation / validation ----------
@app.route("/generate_key", methods=["GET", "POST"])
def generate_key_route():
    try:
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not logged in"}), 401

        # Require loot progress completion
        if int(session.get("loot_progress", 0)) != 3:
            return jsonify({"ok": False, "message": "You must complete all steps"}), 403

        did = str(user.get("id")) if user.get("id") else None
        username = user.get("username", "")

        # Allow custom duration (hours) from POST body, default 24h
        hours = 24
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            hours = int(data.get("hours", 24))

        expires_at = time.time() + (hours * 3600)
        new_key = create_new_key(did, expires_at=expires_at)

        # Reset loot progress
        session["loot_progress"] = 0
        session["loot_progress_expires"] = None

        # Handle special referrer redirect
        ref = request.referrer or ""
        if "loot-link.com" in ref or "lootdest.org" in ref:
            return redirect(f"{FRONTEND_ORIGIN}/keys.html?highlight={new_key}")

        # Normal JSON response
        return jsonify({
            "ok": True,
            "key": new_key,
            "expires_at": expires_at,
            "expires_in": int(expires_at - time.time()),
            "message": f"Welcome {username}, here’s your new key."
        }), 200

    except Exception as e:
        logger.exception(f"Key generation failed for user={session.get('user')}")
        return jsonify({"ok": False, "message": "server error"}), 500


@app.route("/keys", methods=["GET"])
def keys_list():
    try:
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not logged in"}), 401
        did = str(user.get("id"))
        rows = list_keys_for_did(did)  # implement this helper
        formatted = [
            {"key": r[0], "expires_at": r[1], "did": did}
            for r in rows
        ]
        return jsonify({"ok": True, "keys": formatted}), 200
    except Exception:
        logger.exception("Failed to list keys")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/issued_keys", methods=["GET"])
def issued_keys_route():
    try:
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not logged in"}), 401

        did = str(user.get("id"))
        rows = list_keys_for_did(did)  # returns list of rows from DB

        keys = []
        for row in rows:
            keys.append({
                "key": row[0],
                "expires_at": row[1],
                "did": did,
                "used": row[2] if len(row) > 2 else 0
            })

        return jsonify({"ok": True, "keys": keys}), 200

    except Exception:
        logger.exception("Failed to load issued keys")
        return jsonify({"ok": False, "message": "server error"}), 500


@app.route("/revoke_expired", methods=["POST"])
def revoke_expired():
    try:
        revoked = revoke_expired_keys()  # implement this helper
        return jsonify({"ok": True, "revoked": revoked}), 200
    except Exception:
        logger.exception("Failed to revoke expired keys")
        return jsonify({"ok": False, "message": "server error"}), 500


@app.route("/generate_custom_key", methods=["POST"])
def generate_custom_key_route():
    try:
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not logged in"}), 401
        data = request.get_json(silent=True) or {}
        custom_key = data.get("key")
        if "duration_hours" in data:
            duration = int(data.get("duration_hours", 24)) * 3600
        else:
            duration = int(data.get("duration", 86400))
        if not custom_key or len(custom_key) < 4:
            return jsonify({"ok": False, "message": "Key must be at least 4 chars"}), 400
        did = str(user.get("id")) if user.get("id") else None
        new_key = create_custom_key(custom_key, did, duration)
        return jsonify({"ok": True, "key": new_key, "expires_at": time.time() + duration, "message": f"Custom key created for {user.get('username','')}"}), 200
    except Exception:
        logger.exception("Custom key generation failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/validate_key/<path:key>", methods=["GET"])
@app.route("/validate_key/<did>/<path:key>", methods=["GET"])
@app.route("/validate_key", methods=["POST"])
def validate_key_route(key=None, did=None):
    try:
        # Handle POST body
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            key = data.get("key")

        # No key provided
        if not key:
            return jsonify({
                "ok": False,
                "valid": False,
                "message": "no key provided"
            }), 400

        # Normalize key
        key = unquote_plus(key).strip()
        now = time.time()

        # Admin/global override
        if global_override or (did and admin_overrides.get(did)):
            expires_at = int(now) + LEGACY_LIMIT_SECONDS
            return jsonify({
                "ok": True,
                "valid": True,
                "message": "ADMIN OVERRIDE ACTIVE",
                "expires_at": float(expires_at),
                "expires_in": int(expires_at - now)
            }), 200

        # Lookup record
        record = get_key_record(key)
        if not record:
            return jsonify({
                "ok": False,
                "valid": False,
                "message": "Key not found"
            }), 400

        # Parse expiry safely
        try:
            rec_expires_at = float(record.get("expires_at", 0))
        except (ValueError, TypeError, KeyError):
            return jsonify({
                "ok": False,
                "valid": False,
                "message": "Malformed expiry"
            }), 500

        # Expired key
        if now > rec_expires_at:
            burn_key(key)
            return jsonify({
                "ok": False,
                "valid": False,
                "message": "Key expired"
            }), 410

        # Valid key
        return jsonify({
            "ok": True,
            "valid": True,
            "message": "Key is valid",
            "expires_at": rec_expires_at,
            "expires_in": int(rec_expires_at - now)
        }), 200

    except Exception:
        logger.exception(f"Validation failed for key={key}, did={did}")
        return jsonify({
            "ok": False,
            "valid": False,
            "message": "Server error"
        }), 500


# ---------- Admin endpoints ----------
@app.route("/admin/key/<path:key>", methods=["DELETE"])
def admin_burn_key(key):
    try:
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        key = unquote_plus(key).strip()
        burn_key(key)
        return jsonify({"ok": True, "deleted": key, "message": f"Key {key} has been burned."}), 200
    except Exception:
        logger.exception("Failed to burn key")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/logins", methods=["GET"])
def admin_logins():
    try:
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        return jsonify({"ok": True, "logins": login_history}), 200
    except Exception:
        logger.exception("Failed to fetch admin logins")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/override/all", methods=["GET", "POST", "DELETE"])
def override_all():
    try:
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
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
        logger.exception("override_all failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/override/global", methods=["GET", "POST", "DELETE"])
def override_global():
    try:
        user = session.get("user")
        if not (user and (str(user.get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403

        if request.method == "GET":
            return jsonify({
                "ok": True,
                "global_override": bool(global_override)
            }), 200

        if request.method == "POST":
            expires_at = time.time() + (24 * 3600)  # default 24h
            set_global_override(True, expires_at=expires_at)
            return jsonify({
                "ok": True,
                "global_override": True,
                "expires_at": expires_at,
                "expires_in": int(expires_at - time.time())
            }), 200

        if request.method == "DELETE":
            set_global_override(False)
            return jsonify({
                "ok": True,
                "global_override": False
            }), 200

        return jsonify({"ok": False, "message": "Method not allowed"}), 405

    except Exception:
        logger.exception("override_global failed")
        return jsonify({"ok": False, "message": "server error"}), 500


@app.route("/override/<did>", methods=["GET", "POST", "DELETE"])
def override_user(did):
    try:
        user = session.get("user")
        if not (user and (str(user.get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403

        if request.method == "GET":
            return jsonify({
                "ok": True,
                "user_override": bool(admin_overrides.get(did)),
                "discord_id": did
            }), 200

        if request.method == "POST":
            expires_at = time.time() + (24 * 3600)  # default 24h
            set_user_override(did, {"username": "", "discriminator": "", "expires_at": expires_at})
            return jsonify({
                "ok": True,
                "user_override": True,
                "discord_id": did,
                "expires_at": expires_at,
                "expires_in": int(expires_at - time.time())
            }), 200

        if request.method == "DELETE":
            set_user_override(did, None)
            return jsonify({
                "ok": True,
                "user_override": False,
                "discord_id": did
            }), 200

        return jsonify({"ok": False, "message": "Method not allowed"}), 405

    except Exception:
        logger.exception(f"override_user failed for did={did}")
        return jsonify({"ok": False, "message": "server error"}), 500


@app.route("/remove_role_now/<did>", methods=["POST"])
def remove_role_now(did):
    try:
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        success = discord_remove_role(did)
        return jsonify({"ok": success, "discord_id": did}), (200 if success else 500)
    except Exception:
        logger.exception("remove_role_now failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/remove_role_all", methods=["POST"])
def remove_role_all():
    try:
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
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
                r2 = requests.delete(f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}",
                                     headers=headers, timeout=10)
                if r2.status_code in (200, 204):
                    removed.append(did)
                else:
                    failed.append(did)
            except Exception:
                logger.exception("Error removing role")
                failed.append(did)
        return jsonify({"ok": True, "removed_count": len(removed), "failed_count": len(failed), "removed_sample": removed[:10], "failed_sample": failed[:10]}), 200
    except Exception:
        logger.exception("remove_role_all failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/keys/purge", methods=["POST"])
def purge_keys():
    try:
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        purge_expired()
        return jsonify({"ok": True}), 200
    except Exception:
        logger.exception("purge_keys failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/debug/env")
def debug_env():
    return jsonify({"base": LOOTLABS_API_BASE, "key_loaded": bool(LOOTLABS_API_KEY)})

# ---------- Start Step / Checkpoint / Postback / Verify Click ----------
@app.route("/start_step", methods=["POST"])
def start_step():
    data = request.get_json(silent=True) or {}
    try:
        step = int(data.get("step", 0))
    except Exception:
        return jsonify({"ok": False, "message": "invalid step"}), 400
    if step not in (1, 2, 3):
        return jsonify({"ok": False, "message": "invalid step"}), 400

    sid = session.get("_sid")
    if not sid:
        sid = _gen(16)
        session["_sid"] = sid

    token = _gen(32)
    insert_click(token=token, session_id=sid, step=step, status="pending", click_id=None, ttl=3600)
    verifier_dest = f"https://verifier.gaming-mods.com/verify_click?token={token}"
    logger.info("start_step created token=%s step=%s session=%s", token, step, sid)
    return jsonify({"ok": True, "verifier_dest": verifier_dest, "token": token}), 200

@app.route("/checkpoint", methods=["GET", "OPTIONS"])
def checkpoint():
    if request.method == "OPTIONS":
        return ("", 204)
    progress = int(session.get("loot_progress", 0) or 0)
    expires = session.get("loot_progress_expires")
    if expires and time.time() > expires:
        session["loot_progress"] = 0
        progress = 0
    return jsonify({"ok": True, "progress": progress})

@app.route("/postback", methods=["GET", "POST"])
def postback():
    click_id = request.values.get("click") or request.values.get("CLICK_ID") or request.values.get("click_id")
    token = request.values.get("token")
    if not click_id:
        logger.warning("postback called without click id")
        return ("", 204)
    logger.info("postback received click=%s token=%s", click_id, token)
    if token:
        rec = find_click_by_token(token)
        if rec:
            confirm_token(token, click_id)
            logger.info("postback: token %s confirmed -> click %s", token, click_id)
            return ("", 200)
    rec_by_click = find_click_by_clickid(click_id)
    if rec_by_click:
        confirm_clickid(click_id)
        logger.info("postback: existing click mapping confirmed click=%s token=%s", click_id, rec_by_click.get("token"))
        return ("", 200)
    placeholder = placeholder_for_clickid(click_id, step=None, ttl=3600)
    logger.info("postback: created placeholder token=%s for click=%s", placeholder, click_id)
    return ("", 200)

@app.route("/verify_click", methods=["GET"])
def verify_click():
    token = request.args.get("token")
    click_id = request.args.get("click") or request.args.get("CLICK_ID") or request.args.get("click_id")
    logger.info("verify_click called token=%s click=%s ref=%s", token, click_id, request.referrer)
    rec = None
    if token:
        rec = find_click_by_token(token)
    elif click_id:
        rec = find_click_by_clickid(click_id)
    if not rec:
        if click_id:
            placeholder_for_clickid(click_id, step=None, ttl=3600)
        logger.info("verify_click: no record; redirecting pending")
        return redirect(FRONTEND_ORIGIN + "/checkpoint.html?pending=1")
    for _ in range(8):
        rec = find_click_by_token(rec["token"])
        if rec and rec.get("status") == "confirmed":
            break
        time.sleep(0.25)
    if not rec or rec.get("status") != "confirmed":
        logger.info("verify_click: record not confirmed token=%s click=%s status=%s", rec["token"] if rec else None, click_id, rec.get("status") if rec else None)
        return redirect(FRONTEND_ORIGIN + "/checkpoint.html?pending=1")
    step = rec.get("step") or 1
    if rec.get("session_id"):
        session["_sid"] = rec.get("session_id")
    session["loot_progress"] = int(step)
    session["loot_progress_expires"] = time.time() + 24 * 3600
    mark_used(rec["token"])
    logger.info("verify_click: success token=%s step=%s session=%s", rec["token"], step, session.get("_sid"))
    return redirect(FRONTEND_ORIGIN + "/checkpoint.html")

# Legacy shim for old direct routes
@app.route("/checkpoint_step1", methods=["GET"])
def checkpoint_step1_legacy():
    token = request.args.get("token")
    click = request.args.get("click") or request.args.get("CLICK_ID")
    if token:
        return redirect(f"/verify_click?token={token}")
    if click:
        return redirect(f"/verify_click?click={click}")
    return redirect(FRONTEND_ORIGIN + "/checkpoint.html?pending=1")

@app.route("/checkpoint_step2", methods=["GET"])
def checkpoint_step2_legacy():
    return checkpoint_step1_legacy()

@app.route("/checkpoint_step3", methods=["GET"])
def checkpoint_step3_legacy():
    return checkpoint_step1_legacy()

# ---------- Debug / admin ----------
@app.route("/_debug/clicks", methods=["GET"])
def debug_clicks():
    if os.environ.get("DEBUG_ALLOW", "0") != "1":
        return ("", 404)
    with _conn() as conn:
        rows = conn.execute("SELECT token, loot_click_id, session_id, step, status, created_at, confirmed_at, used_at, expires_at FROM clicks ORDER BY created_at DESC LIMIT 200").fetchall()
        sample = [dict(r) for r in rows]
        return jsonify({"count": len(sample), "sample": sample})

@app.route("/debug/keys", methods=["GET"])
def debug_keys():
    if os.environ.get("DEBUG_ALLOW", "0") != "1":
        return ("", 404)
    with _conn() as conn:
        rows = conn.execute("SELECT key, did, expires_at, used FROM issued_keys ORDER BY expires_at DESC LIMIT 200").fetchall()
        sample = [dict(r) for r in rows]
        return jsonify({"count": len(sample), "sample": sample})

# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=os.environ.get("FLASK_DEBUG", "0") == "1")
