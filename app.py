# ---------------------------
# app.py - safe backwards-compatible upgrade
# Paste this file replacing your current app.py (keep a backup first)
# - Keeps original route names exactly
# - Adds admin/api helpers and idempotent migrations
# - Preserves the DB file and schema compatibility (expires_at as REAL)
# ---------------------------
import os
import time
import json
import sqlite3
import secrets
import logging
from datetime import timedelta
from flask import Flask, request, session, jsonify, redirect, render_template_string

# Basic Flask init
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=1)

# Config (same names your repo used)
DB_PATH = os.environ.get("DB_PATH", os.environ.get("ADIME_DB_PATH", "keys.db"))
IONOS_INDEX = os.environ.get("IONOS_INDEX", "https://gaming-mods.com")
OWNER_ID = os.environ.get("OWNER_ID")  # owner discord id string (optional)
# Legacy cap for older clients
LEGACY_LIMIT_SECONDS = 86400

# Logging
logging.basicConfig(level=logging.INFO)
app.logger = logging.getLogger("verifier")
app.logger.setLevel(logging.INFO)

# Ensure DB and required tables exist (idempotent)
def _init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS issued_keys (
            key TEXT PRIMARY KEY,
            did TEXT,
            expires_at REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            note TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER,
            actor_id TEXT,
            action TEXT,
            meta TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS overrides (
            id TEXT PRIMARY KEY,
            expires_at INTEGER,
            created_at INTEGER
        )
        """)
        conn.commit()

_init_db()

# DB helpers
def _conn():
    return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)

def create_new_key_for_did(did: str, duration_seconds: int = 86400):
    with _conn() as conn:
        key = secrets.token_urlsafe(20)
        expires_at = time.time() + duration_seconds
        conn.execute("INSERT OR REPLACE INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
                     (key, did, expires_at))
        conn.commit()
        return key, expires_at

def create_custom_key(custom_key: str, did: str | None, duration_seconds: int):
    with _conn() as conn:
        expires_at = time.time() + duration_seconds
        conn.execute("INSERT OR REPLACE INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
                     (custom_key, did, expires_at))
        conn.commit()
        return custom_key, expires_at

def get_key_record(key):
    with _conn() as conn:
        cur = conn.execute("SELECT key, did, expires_at, used, note FROM issued_keys WHERE key = ?", (key,))
        r = cur.fetchone()
    if not r:
        return None
    return {"key": r[0], "did": r[1], "expires_at": float(r[2]) if r[2] else None, "used": r[3], "note": r[4]}

def list_keys_for_did(did):
    with _conn() as conn:
        rows = conn.execute("SELECT key, expires_at, did, used, note FROM issued_keys WHERE did = ? ORDER BY expires_at DESC", (did,)).fetchall()
    return [{"key": r[0], "expires_at": float(r[1]) if r[1] else None, "did": r[2], "used": r[3], "note": r[4]} for r in rows]

def list_all_keys(limit=2000):
    with _conn() as conn:
        rows = conn.execute("SELECT key, did, expires_at, used, note FROM issued_keys ORDER BY expires_at DESC LIMIT ?", (limit,)).fetchall()
    return [{"key": r[0], "did": r[1], "expires_at": float(r[2]) if r[2] else None, "used": r[3], "note": r[4]} for r in rows]

def delete_key(key):
    with _conn() as conn:
        conn.execute("DELETE FROM issued_keys WHERE key = ?", (key,))
        conn.commit()

def purge_expired_keys():
    with _conn() as conn:
        now = time.time()
        conn.execute("DELETE FROM issued_keys WHERE expires_at < ?", (now,))
        conn.commit()

# overrides table helpers
def set_override(id_, expires_at_ts):
    with _conn() as conn:
        conn.execute("INSERT OR REPLACE INTO overrides (id, expires_at, created_at) VALUES (?, ?, ?)",
                     (id_, int(expires_at_ts), int(time.time())))
        conn.commit()

def get_override(id_):
    with _conn() as conn:
        cur = conn.execute("SELECT id, expires_at, created_at FROM overrides WHERE id = ?", (id_,))
        r = cur.fetchone()
    if not r:
        return None
    return {"id": r[0], "expires_at": int(r[1]) if r[1] else None, "created_at": int(r[2]) if r[2] else None}

def get_active_global_override(now=None):
    now = now or int(time.time())
    with _conn() as conn:
        cur = conn.execute("SELECT expires_at FROM overrides WHERE id = 'GLOBAL'")
        r = cur.fetchone()
        if r and r[0] and int(r[0]) > now:
            return int(r[0])
    return None

# audit log helper
def audit_log(actor_id, action, meta=None):
    try:
        with _conn() as conn:
            conn.execute("INSERT INTO admin_audit (ts, actor_id, action, meta) VALUES (?, ?, ?, ?)",
                         (int(time.time()), str(actor_id) if actor_id else None, action, json.dumps(meta) if meta else None))
            conn.commit()
    except Exception:
        app.logger.exception("audit_log failed")

# admin guard tolerant to session variations
def is_owner_session():
    user = session.get("user", {})
    # allow session['user'] shaped as {"id": "..."} or {"user": {"id": "..."}}
    uid = user.get("id") if isinstance(user, dict) else None
    # fallback nested
    if not uid and isinstance(user, dict) and isinstance(user.get("user"), dict):
        uid = user["user"].get("id")
    if user and user.get("is_admin"):
        return True
    if OWNER_ID and uid and str(uid) == str(OWNER_ID):
        return True
    return False

# -------------------------
# Keep original routes — unchanged names and methods
# -------------------------

@app.route("/portal/me")
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({"ok": True, "user": user}), 200

@app.route("/generate_key", methods=["GET", "POST"])
def generate_key_route():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    did = str(user.get("id")) if user.get("id") else None
    # 24 hours default
    key, expires_at = create_new_key_for_did(did, duration_seconds=24*60*60)
    # For redirect flows (lootlabs) keep original behavior
    ref = request.referrer or ""
    if "loot-link.com" in ref:
        return redirect("https://gaming-mods.com/keys.html")
    return jsonify({"ok": True, "key": key, "expires_at": expires_at, "message": "new key created"}), 200

@app.route("/keys", methods=["GET"])
def keys_list():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    did = str(user.get("id")) if user.get("id") else None
    try:
        rows = list_keys_for_did(did)
        return jsonify({"ok": True, "keys": rows}), 200
    except Exception:
        app.logger.exception("Failed to list keys")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/generate_custom_key", methods=["POST"])
def generate_custom_key_route():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    data = request.get_json(silent=True) or {}
    custom_key = data.get("key")
    # support duration_hours OR duration (seconds) to be compatible
    if "duration_hours" in data:
        duration_seconds = int(data.get("duration_hours", 24)) * 3600
    else:
        duration_seconds = int(data.get("duration", 24*3600))
    if not custom_key or len(custom_key) < 3:
        return jsonify({"ok": False, "message": "key must be at least 3 chars"}), 400
    did = str(user.get("id")) if user.get("id") else None
    try:
        create_custom_key(custom_key, did, duration_seconds)
        audit_log(user.get("id"), "generate_custom_key", {"key": custom_key, "did": did, "expires_at": int(time.time()) + duration_seconds})
        return jsonify({"ok": True, "key": custom_key, "expires_at": int(time.time()) + duration_seconds}), 200
    except Exception:
        app.logger.exception("Custom key generation failed")
        return jsonify({"ok": False, "message": "server error"}), 500

# validate_key must accept both GET /validate_key/<key> and POST /validate_key (legacy forms)
@app.route("/validate_key/<path:key>", methods=["GET"])
@app.route("/validate_key", methods=["POST"])
def validate_key_route(key=None):
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        key = data.get("key")
    if not key:
        return jsonify({"ok": False, "message": "no key provided"}), 400
    key = key.strip()
    now = int(time.time())
    # global override
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
    rec = get_key_record(key)
    if not rec:
        return jsonify({"ok": False, "message": "not found"}), 404
    expires_at = int(rec.get("expires_at") or 0)
    remaining = max(0, expires_at - now) if expires_at else 0
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

# Admin-only endpoints (keeps original admin route names used by admin.html)
@app.route("/admin/api/me", methods=["GET"])
def admin_api_me():
    user = session.get("user") or {}
    return jsonify({"username": user.get("username"), "id": user.get("id"), "is_admin": bool(is_owner_session())}), 200

@app.route("/admin/api/generate_custom_key", methods=["POST"])
def admin_api_generate_custom_key():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    # accept duration_hours or duration
    if "duration_hours" in data:
        duration = int(data.get("duration_hours", 1)) * 3600
    else:
        duration = int(data.get("duration", 3600))
    did = data.get("did") or None
    if not key or len(str(key)) < 3:
        return jsonify({"ok": False, "message": "key too short"}), 400
    try:
        create_custom_key(key, did, duration)
        audit_log(session.get("user", {}).get("id"), "admin_generate_key", {"key": key, "did": did, "expires_at": int(time.time()) + duration})
        return jsonify({"ok": True, "key": key, "expires_at": int(time.time()) + duration}), 200
    except Exception:
        app.logger.exception("admin generate failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/keys", methods=["GET"])
def admin_api_list_keys():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    try:
        keys = list_all_keys()
        return jsonify({"keys": keys}), 200
    except Exception:
        app.logger.exception("admin list failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/revoke_key", methods=["POST"])
def admin_api_revoke_key():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    if not key:
        return jsonify({"ok": False, "message": "no key provided"}), 400
    try:
        delete_key(key)
        audit_log(session.get("user", {}).get("id"), "revoke_key", {"key": key})
        return jsonify({"ok": True}), 200
    except Exception:
        app.logger.exception("admin revoke failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/create_override", methods=["POST"])
def admin_api_create_override():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    id_ = data.get("id")
    if "duration_hours" in data:
        duration = int(data.get("duration_hours", 24)) * 3600
    else:
        duration = int(data.get("duration", 86400))
    if not id_:
        return jsonify({"ok": False, "message": "no id provided"}), 400
    expires_at = int(time.time()) + duration
    try:
        set_override(id_, expires_at)
        audit_log(session.get("user", {}).get("id"), "create_override", {"id": id_, "expires_at": expires_at})
        return jsonify({"ok": True, "id": id_, "expires_at": expires_at}), 200
    except Exception:
        app.logger.exception("admin override failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/overrides", methods=["GET"])
def admin_api_list_overrides():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    try:
        with _conn() as conn:
            cur = conn.execute("SELECT id, expires_at, created_at FROM overrides ORDER BY created_at DESC LIMIT 500")
            rows = cur.fetchall()
        overrides = [{"id": r[0], "expires_at": int(r[1]) if r[1] else None, "created_at": int(r[2]) if r[2] else None} for r in rows]
        return jsonify({"overrides": overrides}), 200
    except Exception:
        app.logger.exception("admin overrides failed")
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

@app.route("/admin/api/validate_key", methods=["POST"])
def admin_api_validate_key():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    if not key:
        return jsonify({"ok": False, "message": "no key provided"}), 400
    return validate_key_route_internal(key)

# small internal validation helper to avoid code duplication
def validate_key_route_internal(key):
    now = int(time.time())
    gexp = get_active_global_override(now=now)
    if gexp:
        rem = max(0, gexp - now)
        return jsonify({"ok": True, "reason": "global override active", "expires_at": gexp, "remaining_seconds": rem, "legacy_remaining_seconds": min(rem, LEGACY_LIMIT_SECONDS), "legacy_duration": LEGACY_LIMIT_SECONDS}), 200
    rec = get_key_record(key)
    if not rec:
        return jsonify({"ok": False, "message": "not found"}), 404
    expires_at = int(rec.get("expires_at") or 0)
    remaining = max(0, expires_at - now) if expires_at else 0
    if expires_at and expires_at < now:
        return jsonify({"ok": False, "message": "expired", "key": rec["key"], "did": rec["did"], "expires_at": expires_at, "remaining_seconds": 0, "legacy_remaining_seconds": 0, "legacy_duration": LEGACY_LIMIT_SECONDS}), 200
    return jsonify({"ok": True, "key": rec["key"], "did": rec["did"], "expires_at": expires_at, "remaining_seconds": remaining, "legacy_remaining_seconds": min(remaining, LEGACY_LIMIT_SECONDS), "legacy_duration": LEGACY_LIMIT_SECONDS}), 200

# Keep existing admin-style routes unchanged name-wise for compatibility with admin.html and keys.html
@app.route("/me", methods=["GET"])
def me_route():
    user = session.get("user") or {}
    return jsonify({"username": user.get("username"), "id": user.get("id"), "is_admin": bool(is_owner_session())}), 200

# optional debug route to inspect session (temporary)
@app.route("/_debug/session", methods=["GET"])
def _debug_session():
    # remove or restrict in production
    data = {"session_keys": list(session.keys()), "session_user": session.get("user")}
    app.logger.debug("SESSION DEBUG: %s", json.dumps(data, default=str))
    return jsonify({"ok": True, "data": data}), 200

# Run
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
