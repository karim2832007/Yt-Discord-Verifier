#!/usr/bin/env python3
# app.py — upgraded, complete, backwards-compatible replacement
# - Preserves all original route names and behavior you provided
# - Adds /health, static admin serving, robust admin API helpers
# - Idempotent DB init compatible with original schema (expires_at REAL)
# - Tolerant owner/admin checks; detailed logging for debugging
# - Sends/accepts durations in seconds or duration_hours where convenient
# Backup your current app.py before replacing.

import os
import time
import secrets
import logging
import json
import sqlite3
from datetime import timedelta
from typing import Optional, Dict, Any, List

import requests
from flask import (
    Flask, redirect, request, session, jsonify, render_template_string,
    url_for, send_from_directory, make_response
)
from flask_cors import CORS
from dotenv import load_dotenv
from urllib.parse import unquote_plus

# -----------------------------------------------------------------------------
# Config / app init
# -----------------------------------------------------------------------------
load_dotenv()
app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))# ---------- Replacement: persistent click mapping + start_step/checkpoint/postback/verify_click ----------
import sqlite3
import logging
from flask import g

LOGGER = logging.getLogger("verifier.clicks")
LOGGER.setLevel(logging.INFO)

CLICK_DB = os.environ.get("CLICK_DB", os.path.join(os.getcwd(), "clicks.sqlite"))
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "https://gaming-mods.com")

def _get_db():
    db = getattr(g, "_click_db", None)
    if db is None:
        db = sqlite3.connect(CLICK_DB, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
        g._click_db = db
    return db

@app.teardown_appcontext
def _close_db(exc):
    db = getattr(g, "_click_db", None)
    if db is not None:
        db.close()

def _ensure_table():
    db = _get_db()
    db.execute("""
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
    db.commit()

# ensure table exists
with app.app_context():
    _ensure_table()

def _now():
    return int(time.time())

def _gen(n=24):
    return secrets.token_urlsafe(n)

def _insert_click(token, session_id, step, status="pending", click_id=None, ttl=3600):
    db = _get_db()
    now = _now()
    expires = now + int(ttl)
    db.execute(
        "INSERT OR REPLACE INTO clicks (token, loot_click_id, session_id, step, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (token, click_id, session_id, step, status, now, expires)
    )
    db.commit()

def _find_by_token(token):
    if not token: return None
    row = _get_db().execute("SELECT * FROM clicks WHERE token = ? LIMIT 1", (token,)).fetchone()
    return dict(row) if row else None

def _find_by_clickid(click_id):
    if not click_id: return None
    row = _get_db().execute("SELECT * FROM clicks WHERE loot_click_id = ? LIMIT 1", (click_id,)).fetchone()
    return dict(row) if row else None

def _confirm_token(token, click_id):
    now = _now()
    db = _get_db()
    db.execute("UPDATE clicks SET status='confirmed', loot_click_id=?, confirmed_at=? WHERE token=?", (click_id, now, token))
    db.commit()

def _confirm_clickid(click_id):
    now = _now()
    db = _get_db()
    row = db.execute("SELECT token FROM clicks WHERE loot_click_id = ? LIMIT 1", (click_id,)).fetchone()
    if row:
        token = row["token"]
        db.execute("UPDATE clicks SET status='confirmed', confirmed_at=? WHERE token=?", (now, token))
        db.commit()
        return token
    return None

def _placeholder_for_clickid(click_id, step=None, ttl=3600):
    token = _gen(28)
    now = _now()
    expires = now + int(ttl)
    db = _get_db()
    db.execute(
        "INSERT INTO clicks (token, loot_click_id, session_id, step, status, created_at, confirmed_at, expires_at) VALUES (?, ?, ?, ?, 'confirmed', ?, ?, ?)",
        (token, click_id, None, step, now, now, expires)
    )
    db.commit()
    return token

def _mark_used(token):
    now = _now()
    db = _get_db()
    db.execute("UPDATE clicks SET status='used', used_at=? WHERE token=?", (now, token))
    db.commit()

# ---- CORS helper (keeps behavior you had) ----
@app.after_request
def _add_cors(resp):
    origin = request.headers.get("Origin", "")
    if origin == FRONTEND_ORIGIN:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Vary"] = "Origin"
    return resp

# ---- Start Step ----
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
    _insert_click(token=token, session_id=sid, step=step, status="pending", click_id=None, ttl=3600)
    verifier_dest = f"https://verifier.gaming-mods.com/verify_click?token={token}"
    LOGGER.info("start_step created token=%s step=%s session=%s", token, step, sid)
    return jsonify({"ok": True, "verifier_dest": verifier_dest, "token": token}), 200

# ---- Checkpoint ----
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

# ---- Postback ----
@app.route("/postback", methods=["GET", "POST"])
def postback():
    click_id = request.values.get("click") or request.values.get("CLICK_ID") or request.values.get("click_id")
    token = request.values.get("token")
    if not click_id:
        return ("", 204)

    LOGGER.info("postback received click=%s token=%s", click_id, token)

    if token:
        rec = _find_by_token(token)
        if rec:
            _confirm_token(token, click_id)
            LOGGER.info("postback: token %s confirmed -> click %s", token, click_id)
            return ("", 200)

    rec = _find_by_clickid(click_id)
    if rec:
        _confirm_clickid(click_id)
        LOGGER.info("postback: existing click mapping confirmed click=%s token=%s", click_id, rec.get("token"))
        return ("", 200)

    placeholder = _placeholder_for_clickid(click_id, step=None, ttl=3600)
    LOGGER.info("postback: created placeholder token=%s for click=%s", placeholder, click_id)
    return ("", 200)

# ---- Verify Click ----
@app.route("/verify_click", methods=["GET"])
def verify_click():
    token = request.args.get("token")
    click_id = request.args.get("click") or request.args.get("CLICK_ID") or request.args.get("click_id")
    LOGGER.info("verify_click called token=%s click=%s ref=%s", token, click_id, request.referrer)

    rec = None
    if token:
        rec = _find_by_token(token)
    elif click_id:
        rec = _find_by_clickid(click_id)

    if not rec:
        if click_id:
            _placeholder_for_clickid(click_id, step=None, ttl=3600)
        LOGGER.info("verify_click: no record; redirecting pending")
        return redirect(FRONTEND_ORIGIN + "/checkpoint.html?pending=1")

    # wait briefly for postback to mark confirmed (race tolerance)
    for _ in range(8):
        rec = _find_by_token(rec["token"])
        if rec and rec.get("status") == "confirmed":
            break
        time.sleep(0.25)

    if not rec or rec.get("status") != "confirmed":
        LOGGER.info("verify_click: record not confirmed token=%s click=%s status=%s", rec["token"] if rec else None, click_id, rec.get("status") if rec else None)
        return redirect(FRONTEND_ORIGIN + "/checkpoint.html?pending=1")

    # confirmed: map progress to session
    step = rec.get("step") or 1
    if rec.get("session_id"):
        session["_sid"] = rec.get("session_id")
    session["loot_progress"] = int(step)
    session["loot_progress_expires"] = time.time() + 24 * 3600
    _mark_used(rec["token"])
    LOGGER.info("verify_click: success token=%s step=%s session=%s", rec["token"], step, session.get("_sid"))
    return redirect(FRONTEND_ORIGIN + "/checkpoint.html")

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

# Persistent state
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
OWNER_ID = os.environ.get("OWNER_ID")  # optional owner Discord ID string

# Legacy cap for older clients
LEGACY_LIMIT_SECONDS = 86400

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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS admin_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER,
                    actor_id TEXT,
                    action TEXT,
                    meta TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS overrides (
                    id TEXT PRIMARY KEY,
                    expires_at INTEGER,
                    created_at INTEGER
                )
            """)
            conn.commit()
    except Exception:
        app.logger.exception("Failed to init DB")

init_db()

def _conn():
    return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)

# Key helpers
def create_new_key(did: Optional[str]) -> str:
    with _conn() as conn:
        if did:
            conn.execute("DELETE FROM issued_keys WHERE did = ?", (did,))
        key = secrets.token_urlsafe(10)
        expires_at = time.time() + 24 * 60 * 60
        conn.execute(
            "INSERT INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
            (key, did, expires_at)
        )
        conn.commit()
    return key

def create_custom_key(custom_key: str, did: Optional[str], duration_seconds: int) -> str:
    with _conn() as conn:
        if did:
            conn.execute("DELETE FROM issued_keys WHERE did = ?", (did,))
        expires_at = time.time() + duration_seconds
        conn.execute(
            "INSERT OR REPLACE INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
            (custom_key, did, expires_at)
        )
        conn.commit()
    return custom_key

def get_key_record(key: str) -> Optional[dict]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT did, expires_at, used FROM issued_keys WHERE key = ?",
            (key,)
        ).fetchone()
        if row:
            return {"did": row[0], "expires_at": row[1], "used": row[2]}
    return None

def burn_key(key: str):
    with _conn() as conn:
        conn.execute("DELETE FROM issued_keys WHERE key = ?", (key,))
        conn.commit()

def list_keys() -> list:
    with _conn() as conn:
        rows = conn.execute("SELECT key, expires_at, did FROM issued_keys ORDER BY expires_at DESC").fetchall()
        return [{"key": r[0], "expires_at": r[1], "did": r[2]} for r in rows]

def list_keys_for_did(did: str) -> list:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT key, expires_at FROM issued_keys WHERE did = ? ORDER BY expires_at DESC",
            (did,)
        ).fetchall()
        return [{"key": r[0], "expires_at": r[1]} for r in rows]

def purge_expired():
    with _conn() as conn:
        now = time.time()
        conn.execute("DELETE FROM issued_keys WHERE expires_at < ?", (now,))
        conn.commit()

# Overrides helpers
def set_override(id_: str, expires_at_ts: int) -> None:
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

# Audit log helper
def audit_log(actor_id: Optional[str], action: str, meta: Optional[Dict] = None) -> None:
    try:
        with _conn() as conn:
            conn.execute("INSERT INTO admin_audit (ts, actor_id, action, meta) VALUES (?, ?, ?, ?)",
                         (int(time.time()), str(actor_id) if actor_id else None, action, json.dumps(meta) if meta else None))
            conn.commit()
    except Exception:
        app.logger.exception("audit_log failed")

# -----------------------------------------------------------------------------
# Discord helpers: token exchange, user, guild member, role operations
# -----------------------------------------------------------------------------
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
        raw = r.text
        if r.status_code == 429:
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
def login_error_page(title, brief, body_preview, home):
    tpl = f"""
    <html><body style="font-family:system-ui,Segoe UI,Roboto,Arial">
      <h1>{title}</h1>
      <pre>{brief}</pre>
      <pre>{body_preview}</pre>
      <p><a href="{home}">Return</a></p>
    </body></html>
    """
    return render_template_string(tpl), 400

def rate_limit_page(retry_after, body_preview, retry_link, home):
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


# In-memory stores (replace with Redis/DB in production)
clicks_store = {}
clicks_by_clickid = {}

# ---- CORS ----
@app.after_request
def add_cors(resp):
    origin = request.headers.get('Origin', '')
    if origin == 'https://gaming-mods.com':
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
    resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    resp.headers['Vary'] = 'Origin'
    return resp

# ---- Checkpoint ----
@app.route('/checkpoint', methods=['GET', 'OPTIONS'])
def checkpoint():
    if request.method == 'OPTIONS':
        return ('', 204)
    progress = int(session.get('loot_progress', 0) or 0)
    expires = session.get('loot_progress_expires')
    if expires and time.time() > expires:
        progress = 0
        session['loot_progress'] = 0
    return jsonify({'ok': True, 'progress': progress})

# ---- Postback ----
@app.route('/postback', methods=['GET','POST'])
def postback():
    click_id = request.values.get('click') or request.values.get('CLICK_ID')
    token = request.values.get('token')
    if not click_id:
        return ('', 204)

    if token and token in clicks_store:
        clicks_store[token]['status'] = 'confirmed'
        clicks_store[token]['click_id'] = click_id
        clicks_by_clickid[click_id] = token
        return ('', 200)

    if click_id in clicks_by_clickid:
        t = clicks_by_clickid[click_id]
        clicks_store[t]['status'] = 'confirmed'
        clicks_store[t]['click_id'] = click_id
        return ('', 200)

    # Create placeholder if unmapped
    token0 = secrets.token_urlsafe(24)
    clicks_store[token0] = {
        'token': token0,
        'session_id': None,
        'step': None,
        'created_at': time.time(),
        'expires_at': time.time() + 3600,
        'status': 'confirmed',
        'click_id': click_id
    }
    clicks_by_clickid[click_id] = token0
    return ('', 200)

# ---- Verify Click ----
@app.route('/verify_click', methods=['GET'])
def verify_click():
    token = request.args.get('token')
    click_id = request.args.get('click')
    record = None

    if token:
        record = clicks_store.get(token)
    elif click_id:
        tk = clicks_by_clickid.get(click_id)
        if tk:
            record = clicks_store.get(tk)

    if not record:
        return redirect('https://gaming-mods.com/checkpoint.html?error=access_denied')

    # tolerate race with postback
    for _ in range(3):
        if record.get('status') == 'confirmed':
            break
        time.sleep(0.3)

    if record.get('status') != 'confirmed':
        return redirect('https://gaming-mods.com/checkpoint.html?error=not_confirmed')

    session['_sid'] = record.get('session_id') or session.get('_sid', secrets.token_urlsafe(16))
    session['loot_progress'] = int(record.get('step') or 0)
    session['loot_progress_expires'] = time.time() + 24*3600
    record['status'] = 'used'
    record['used_at'] = time.time()

    return redirect('https://gaming-mods.com/checkpoint.html')


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
            return jsonify({
                "ok": True, "member": True, "role_granted": True,
                "username": "GLOBAL_OVERRIDE", "message": "GLOBAL OVERRIDE ACTIVE"
            }), 200

        if admin_overrides.get(did):
            return jsonify({
                "ok": True, "member": True, "role_granted": True,
                "username": "ADMIN_OVERRIDE", "message": "ADMIN OVERRIDE"
            }), 200

        member = discord_member(did)
        if "user" in member:
            username = member.get("user", {}).get("username", "")
            return jsonify({
                "ok": True, "member": True, "role_granted": True,
                "username": username,
                "message": f"Welcome {username}! Don’t forget to get your key from the website."
            }), 200

        return jsonify({
            "ok": False, "member": False, "role_granted": False,
            "message": f"Member lookup error (status {member.get('status_code')})"
        }), 404
    except Exception:
        app.logger.exception("Error in /status")
        return jsonify({"ok": False, "message": "internal error"}), 500

@app.route("/health", methods=["GET", "HEAD"])
def health():
    return jsonify({"ok": True, "ts": int(time.time())}), 200

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

# -----------------------------------------------------------------------------
# Generate a new key (allow GET for LootLabs redirect + POST for UI)
# -----------------------------------------------------------------------------
@app.route("/generate_key", methods=["GET", "POST"])
def generate_key_route():
    try:
        # Require login
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not logged in"}), 401

        # Require all steps complete
        if int(session.get("loot_progress", 0)) != 3:
            return jsonify({"ok": False, "message": "You must complete all steps"}), 403

        did = str(user.get("id")) if user.get("id") else None
        username = user.get("username", "")

        # Create and persist new key
        new_key = create_new_key(did)

        # Reset progress after key generation
        session["loot_progress"] = 0
        session["loot_progress_expires"] = None

        # If coming from LootLabs redirect, send user back to keys page
        ref = request.referrer or ""
        if "loot-link.com" in ref or "lootdest.org" in ref:
            return redirect("https://gaming-mods.com/keys.html?highlight=" + new_key)

        # Otherwise return JSON for UI
        return jsonify({
            "ok": True,
            "key": new_key,
            "expires_at": time.time() + 24*60*60,
            "message": f"Welcome {username}, here’s your new key."
        }), 200

    except Exception:
        app.logger.exception("Key generation failed")
        return jsonify({"ok": False, "message": "server error"}), 500


# -----------------------------------------------------------------------------
# List all keys for the logged-in user
# -----------------------------------------------------------------------------
@app.route("/keys", methods=["GET"])
def keys_list():
    try:
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not logged in"}), 401

        did = str(user.get("id"))
        rows = list_keys_for_did(did)

        formatted = []
        for r in rows:
            formatted.append({
                "key": r[0] if isinstance(r, (list, tuple)) else r.get("key"),
                "expires_at": r[1] if isinstance(r, (list, tuple)) else r.get("expires_at"),
                "did": did
            })

        return jsonify({"ok": True, "keys": formatted}), 200

    except Exception:
        app.logger.exception("Failed to list keys")
        return jsonify({"ok": False, "message": "server error"}), 500

# -----------------------------------------------------------------------------
# Burn a key (admin only)
# -----------------------------------------------------------------------------
@app.route("/admin/key/<path:key>", methods=["DELETE"])
def admin_burn_key(key):
    try:
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403

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

# -----------------------------------------------------------------------------
# Create custom key (user)
# -----------------------------------------------------------------------------
@app.route("/generate_custom_key", methods=["POST"])
def generate_custom_key_route():
    try:
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not logged in"}), 401

        data = request.get_json(silent=True) or {}
        custom_key = data.get("key")
        # accept either duration_hours or duration (seconds)
        if "duration_hours" in data:
            duration = int(data.get("duration_hours", 24)) * 3600
        else:
            duration = int(data.get("duration", 86400))

        if not custom_key or len(custom_key) < 4:
            return jsonify({"ok": False, "message": "Key must be at least 4 chars"}), 400

        did = str(user.get("id")) if user.get("id") else None
        new_key = create_custom_key(custom_key, did, duration)

        return jsonify({
            "ok": True,
            "key": new_key,
            "expires_at": time.time() + duration,
            "message": f"Custom key created for {user.get('username', '')}"
        }), 200
    except Exception:
        app.logger.exception("Custom key generation failed")
        return jsonify({"ok": False, "message": "server error"}), 500

# -----------------------------------------------------------------------------
# Validate a key (fix Android encoding issues); supports GET and POST via admin API too
# -----------------------------------------------------------------------------
@app.route("/validate_key/<path:key>", methods=["GET"])
@app.route("/validate_key/<did>/<path:key>", methods=["GET"])
@app.route("/validate_key", methods=["POST"])
def validate_key_route(key=None, did=None):
    try:
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            key = data.get("key")

        if not key:
            return jsonify({"ok": False, "valid": False, "message": "no key provided"}), 400

        key = unquote_plus(key).strip()
        now = time.time()

        # Global or admin override
        if global_override or (did and admin_overrides.get(did)):
            expires_at = int(now) + LEGACY_LIMIT_SECONDS
            return jsonify({
                "ok": True,
                "valid": True,
                "message": "ADMIN OVERRIDE ACTIVE",
                "expires_at": float(expires_at),
                "expires_in": int(expires_at - now)
            }), 200

        record = get_key_record(key)
        if not record:
            return jsonify({"ok": False, "valid": False, "message": "Key not found"}), 400

        try:
            rec_expires_at = float(record["expires_at"])
        except (KeyError, ValueError, TypeError):
            return jsonify({"ok": False, "valid": False, "message": "Malformed expiry"}), 500

        if now > rec_expires_at:
            burn_key(key)  # keep your existing behavior on expiry
            return jsonify({"ok": False, "valid": False, "message": "Key expired"}), 410

        # Key is valid — return precise expiry info
        return jsonify({
            "ok": True,
            "valid": True,
            "message": "Key is valid",
            "expires_at": float(rec_expires_at),
            "expires_in": int(rec_expires_at - now)
        }), 200

    except Exception:
        app.logger.exception("Validation failed")
        return jsonify({"ok": False, "valid": False, "message": "Server error"}), 500


# -----------------------------------------------------------------------------
# Admin logins listing
# -----------------------------------------------------------------------------
@app.route("/admin/logins", methods=["GET"])
def admin_logins():
    try:
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        return jsonify({"ok": True, "logins": login_history}), 200
    except Exception:
        app.logger.exception("Failed to fetch admin logins")
        return jsonify({"ok": False, "message": "server error"}), 500

# -----------------------------------------------------------------------------
# Overrides (owner only)
# -----------------------------------------------------------------------------
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
        app.logger.exception("override_all failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/override/<did>", methods=["GET", "POST", "DELETE"])
def override_user(did):
    try:
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
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
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        success = discord_remove_role(did)
        return jsonify({"ok": success, "discord_id": did}), (200 if success else 500)
    except Exception:
        app.logger.exception("remove_role_now failed")
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
        if not (session.get("user") and (str(session.get("user").get("id")) == str(OWNER_ID) if OWNER_ID else False)):
            return jsonify({"ok": False, "message": "Forbidden"}), 403
        purge_expired()
        return jsonify({"ok": True}), 200
    except Exception:
        app.logger.exception("purge_keys failed")
        return jsonify({"ok": False, "message": "server error"}), 500

# -----------------------------------------------------------------------------
# Debug helpers
# -----------------------------------------------------------------------------
@app.route("/debug/env")
def debug_env():
    return jsonify({
        "base": LOOTLABS_API_BASE,
        "key_loaded": bool(LOOTLABS_API_KEY)
    })

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

# -----------------------------------------------------------------------------
# Admin API endpoints for admin.html (preserve names)
# -----------------------------------------------------------------------------
def is_owner_session() -> bool:
    owner = os.environ.get("OWNER_ID") or OWNER_ID
    user = session.get("user")
    if not user or not owner:
        return False
    if isinstance(user, dict) and user.get("is_admin"):
        return True
    return str(user.get("id")) == str(owner)

@app.route("/admin/api/me", methods=["GET"])
def admin_api_me():
    user = session.get("user") or {}
    return jsonify({
        "username": user.get("username"),
        "id": user.get("id"),
        "is_admin": bool(is_owner_session())
    }), 200

@app.route("/admin/api/generate_custom_key", methods=["POST"])
def admin_api_generate_custom_key():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    # accept duration_hours or duration (seconds)
    if "duration_hours" in data:
        duration = int(data.get("duration_hours", 1)) * 3600
    else:
        duration = int(data.get("duration", 3600))
    did = data.get("did") or None
    note = data.get("note") or ""
    if not key or len(key) < 3:
        return jsonify({"ok": False, "message": "key too short"}), 400
    if did:
        if not str(did).isdigit() or not (16 <= len(str(did)) <= 21):
            return jsonify({"ok": False, "message": "invalid discord id"}), 400
    expires_at = int(time.time()) + duration
    try:
        with _conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
                (key, did, expires_at)
            )
            conn.commit()
        audit_log(session.get("user", {}).get("id"), "admin_generate_key", {"key": key, "did": did, "expires_at": expires_at})
        return jsonify({'ok': True, 'key': key, 'expires_at': expires_at}), 200
    except Exception:
        app.logger.exception("admin generate_custom_key failed")
        return jsonify({'ok': False, 'message': 'server error'}), 500

@app.route("/admin/api/keys", methods=["GET"])
def admin_api_list_keys():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    try:
        with _conn() as conn:
            cur = conn.execute("SELECT key, did, expires_at, used FROM issued_keys ORDER BY expires_at DESC LIMIT 2000")
            rows = cur.fetchall()
        keys = [{'key': r[0], 'did': r[1], 'expires_at': r[2], 'used': r[3]} for r in rows]
        return jsonify({'keys': keys}), 200
    except Exception:
        app.logger.exception("admin list_keys failed")
        return jsonify({'ok': False, 'message': 'server error'}), 500

@app.route("/admin/api/revoke_key", methods=["POST"])
def admin_api_revoke_key():
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
        app.logger.exception("admin revoke_key failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/create_override", methods=["POST"])
def admin_api_create_override():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    id_ = data.get("id")
    # accept duration_hours or duration (seconds)
    if "duration_hours" in data:
        duration = int(data.get("duration_hours", 24)) * 3600
    else:
        duration = int(data.get("duration", 86400))
    if not id_:
        return jsonify({"ok": False, "message": "no id provided"}), 400
    if id_ != "GLOBAL":
        if not str(id_).isdigit() or not (16 <= len(str(id_)) <= 21):
            return jsonify({"ok": False, "message": "invalid discord id"}), 400
    expires_at = int(time.time()) + duration
    try:
        if id_ == "GLOBAL":
            set_global_override(True)
        else:
            set_user_override(id_, {"created_at": int(time.time()), "expires_at": expires_at})
        audit_log(session.get("user", {}).get("id"), "create_override", {"id": id_, "expires_at": expires_at})
        return jsonify({"ok": True, "id": id_, "expires_at": expires_at}), 200
    except Exception:
        app.logger.exception("admin create_override failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/overrides", methods=["GET"])
def admin_api_list_overrides():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    try:
        overrides = []
        if global_override:
            overrides.append({"id": "GLOBAL", "active": True})
        for did, info in admin_overrides.items():
            overrides.append({"id": did, "info": info})
        return jsonify({"overrides": overrides}), 200
    except Exception:
        app.logger.exception("admin list_overrides failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/validate_key", methods=["POST"])
def admin_api_validate_key():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    if not key:
        return jsonify({"ok": False, "message": "no key provided"}), 400
    try:
        now = int(time.time())
        gexp = get_active_global_override(now=now)
        if gexp:
            remaining = max(0, gexp - now)
            return jsonify({
                "ok": True,
                "reason": "global override active",
                "expires_at": gexp,
                "remaining_seconds": remaining,
                "legacy_remaining_seconds": min(remaining, LEGACY_LIMIT_SECONDS),
                "legacy_duration": LEGACY_LIMIT_SECONDS
            }), 200
        with _conn() as conn:
            cur = conn.execute("SELECT key, did, expires_at, used FROM issued_keys WHERE key = ?", (key,))
            r = cur.fetchone()
        if not r:
            return jsonify({"ok": False, "message": "not found"}), 404
        expires_at = int(r[2]) if r[2] else 0
        remaining = max(0, expires_at - now) if expires_at else 0
        if expires_at and expires_at < now:
            return jsonify({"ok": False, "message": "expired", "key": r[0], "did": r[1], "expires_at": expires_at, "remaining_seconds": 0, "legacy_remaining_seconds": 0, "legacy_duration": LEGACY_LIMIT_SECONDS}), 200
        return jsonify({"ok": True, "key": r[0], "did": r[1], "expires_at": expires_at, "remaining_seconds": remaining, "legacy_remaining_seconds": min(remaining, LEGACY_LIMIT_SECONDS), "legacy_duration": LEGACY_LIMIT_SECONDS}), 200
    except Exception:
        app.logger.exception("admin validate failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/audit", methods=["GET"])
def admin_api_audit():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    try:
        with _conn() as conn:
            cur = conn.execute("SELECT id, ts, actor_id, action, meta FROM admin_audit ORDER BY ts DESC LIMIT 200")
            rows = cur.fetchall()
        logs = [{"id": r[0], "ts": int(r[1]) if r[1] else None, "actor_id": r[2], "action": r[3], "meta": json.loads(r[4]) if r[4] else None} for r in rows]
        return jsonify({"logs": logs}), 200
    except Exception:
        app.logger.exception("admin audit failed")
        return jsonify({"ok": False, "message": "server error"}), 500

# -----------------------------------------------------------------------------
# Misc compatibility endpoints
# -----------------------------------------------------------------------------
@app.route("/me", methods=["GET"])
def me_route():
    user = session.get("user") or {}
    return jsonify({"username": user.get("username"), "id": user.get("id"), "is_admin": bool(is_owner_session())}), 200

@app.route("/_debug/session", methods=["GET"])
def _debug_session():
    data = {"session_keys": list(session.keys()), "session_user": session.get("user")}
    app.logger.debug("SESSION DEBUG: %s", json.dumps(data, default=str))
    return jsonify({"ok": True, "data": data}), 200

# -----------------------------------------------------------------------------
# Serve admin UI fallback if placed in static/admin.html
# -----------------------------------------------------------------------------
@app.route("/admin.html", methods=["GET"])
@app.route("/admin", methods=["GET"])
def serve_admin():
    try:
        return send_from_directory(app.static_folder or "static", "admin.html")
    except Exception:
        return make_response("Admin UI not found on server (static/admin.html).", 404)

# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", os.environ.get("FLASK_RUN_PORT", 5000)))
    app.logger.info("Starting app on 0.0.0.0:%s", port)
    app.run(host="0.0.0.0", port=port)
