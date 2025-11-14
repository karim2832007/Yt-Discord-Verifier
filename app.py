#!/usr/bin/env python3
# app.py — full replacement (backwards-compatible)
# - Keeps all original public and admin route names unchanged
# - Adds /health and static admin serving for platform probes
# - Idempotent DB initialization compatible with existing schema
# - Tolerant admin session check and detailed error logging
# - Use this file to replace your current app.py (backup first)

import os
import time
import json
import sqlite3
import secrets
import logging
from datetime import timedelta
from typing import Optional, Any, Dict
from flask import (
    Flask,
    request,
    session,
    jsonify,
    redirect,
    send_from_directory,
    make_response,
)

# ---------- Configuration ----------
app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=1)

DB_PATH = os.environ.get("DB_PATH", os.environ.get("ADIME_DB_PATH", "keys.db"))
OWNER_ID = os.environ.get("OWNER_ID")  # optional owner Discord ID string
LEGACY_LIMIT_SECONDS = 86400  # legacy cap for older clients

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("adime_verifier")
logger.setLevel(logging.INFO)

# ---------- Health + static admin ----------
@app.route("/health", methods=["GET", "HEAD"])
def health():
    return make_response("OK", 200)

@app.route("/", methods=["GET"])
@app.route("/admin", methods=["GET"])
def serve_admin():
    # serve static/admin.html if present
    try:
        return send_from_directory(app.static_folder or "static", "admin.html")
    except Exception:
        return make_response("Admin UI not found on server (static/admin.html).", 404)

# ---------- Database init and helpers ----------
def _init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS issued_keys (
                key TEXT PRIMARY KEY,
                did TEXT,
                expires_at REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                note TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER,
                actor_id TEXT,
                action TEXT,
                meta TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS overrides (
                id TEXT PRIMARY KEY,
                expires_at INTEGER,
                created_at INTEGER
            )
            """
        )
        conn.commit()

_init_db()

def _conn():
    return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)

def now_ts() -> int:
    return int(time.time())

# Key helpers
def create_new_key_for_did(did: Optional[str], duration_seconds: int = 86400) -> Dict[str, Any]:
    key = secrets.token_urlsafe(20)
    expires_at = time.time() + duration_seconds
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
            (key, did, expires_at),
        )
        conn.commit()
    return {"key": key, "expires_at": int(expires_at), "did": did}

def create_custom_key(custom_key: str, did: Optional[str], duration_seconds: int) -> Dict[str, Any]:
    expires_at = time.time() + duration_seconds
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO issued_keys (key, did, expires_at, used) VALUES (?, ?, ?, 0)",
            (custom_key, did, expires_at),
        )
        conn.commit()
    return {"key": custom_key, "expires_at": int(expires_at), "did": did}

def get_key_record(key: str) -> Optional[Dict[str, Any]]:
    with _conn() as conn:
        cur = conn.execute(
            "SELECT key, did, expires_at, used, note FROM issued_keys WHERE key = ?",
            (key,),
        )
        r = cur.fetchone()
    if not r:
        return None
    return {"key": r[0], "did": r[1], "expires_at": float(r[2]) if r[2] is not None else None, "used": r[3], "note": r[4]}

def list_keys_for_did(did: Optional[str]) -> list:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT key, did, expires_at, used, note FROM issued_keys WHERE did = ? ORDER BY expires_at DESC",
            (did,),
        ).fetchall()
    return [
        {"key": r[0], "did": r[1], "expires_at": float(r[2]) if r[2] else None, "used": r[3], "note": r[4]}
        for r in rows
    ]

def list_all_keys(limit: int = 2000) -> list:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT key, did, expires_at, used, note FROM issued_keys ORDER BY expires_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {"key": r[0], "did": r[1], "expires_at": float(r[2]) if r[2] else None, "used": r[3], "note": r[4]}
        for r in rows
    ]

def delete_key(key: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM issued_keys WHERE key = ?", (key,))
        conn.commit()

def purge_expired_keys() -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM issued_keys WHERE expires_at < ?", (time.time(),))
        conn.commit()

# Overrides helpers
def set_override(id_: str, expires_at_ts: int) -> None:
    with _conn() as conn:
        conn.execute("INSERT OR REPLACE INTO overrides (id, expires_at, created_at) VALUES (?, ?, ?)", (id_, int(expires_at_ts), now_ts()))
        conn.commit()

def get_override(id_: str) -> Optional[Dict[str, Any]]:
    with _conn() as conn:
        cur = conn.execute("SELECT id, expires_at, created_at FROM overrides WHERE id = ?", (id_,))
        r = cur.fetchone()
    if not r:
        return None
    return {"id": r[0], "expires_at": int(r[1]) if r[1] else None, "created_at": int(r[2]) if r[2] else None}

def get_active_global_override(now: Optional[int] = None) -> Optional[int]:
    now = now or now_ts()
    with _conn() as conn:
        cur = conn.execute("SELECT expires_at FROM overrides WHERE id = 'GLOBAL'")
        r = cur.fetchone()
        if r and r[0] and int(r[0]) > now:
            return int(r[0])
    return None

# Audit
def audit_log(actor_id: Optional[str], action: str, meta: Optional[Dict] = None) -> None:
    try:
        with _conn() as conn:
            conn.execute("INSERT INTO admin_audit (ts, actor_id, action, meta) VALUES (?, ?, ?, ?)", (now_ts(), actor_id, action, json.dumps(meta) if meta else None))
            conn.commit()
    except Exception:
        logger.exception("audit_log failed")

# ---------- Session / admin guard ----------
def is_owner_session() -> bool:
    user = session.get("user") or {}
    if isinstance(user, dict) and user.get("is_admin"):
        return True
    uid = None
    if isinstance(user, dict):
        uid = user.get("id") or (user.get("user") and user.get("user").get("id"))
    if OWNER_ID and uid and str(uid) == str(OWNER_ID):
        return True
    return False

# ---------- Public / legacy routes (names preserved) ----------
@app.route("/portal/me", methods=["GET"])
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
    did = str(user.get("id")) if isinstance(user, dict) and user.get("id") else None
    key_data = create_new_key_for_did(did, duration_seconds=24 * 3600)
    # legacy redirect behavior preserved if needed
    ref = request.referrer or ""
    if "loot-link.com" in ref:
        return redirect("/keys.html")
    return jsonify({"ok": True, "key": key_data["key"], "expires_at": key_data["expires_at"]}), 200

@app.route("/keys", methods=["GET"])
def keys_list():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    did = str(user.get("id")) if isinstance(user, dict) and user.get("id") else None
    try:
        rows = list_keys_for_did(did)
        return jsonify({"ok": True, "keys": rows}), 200
    except Exception:
        logger.exception("Failed to list keys")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/generate_custom_key", methods=["POST"])
def generate_custom_key_route():
    if not session.get("user"):
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    data = request.get_json(silent=True) or {}
    custom_key = data.get("key")
    if "duration_hours" in data:
        duration_seconds = int(data.get("duration_hours", 24)) * 3600
    else:
        duration_seconds = int(data.get("duration", 24 * 3600))
    if not custom_key or len(str(custom_key)) < 3:
        return jsonify({"ok": False, "message": "key must be at least 3 chars"}), 400
    did = data.get("did") or (session.get("user") and session["user"].get("id"))
    try:
        create_custom_key(custom_key, did, duration_seconds)
        audit_log(session.get("user", {}).get("id"), "generate_custom_key", {"key": custom_key, "did": did, "duration_seconds": duration_seconds})
        return jsonify({"ok": True, "key": custom_key, "expires_at": int(time.time()) + duration_seconds}), 200
    except Exception:
        logger.exception("Custom key generation failed")
        return jsonify({"ok": False, "message": "server error"}), 500

# Accept GET /validate_key/<key> and POST /validate_key
@app.route("/validate_key/<path:key>", methods=["GET"])
@app.route("/validate_key", methods=["POST"])
def validate_key_route(key: Optional[str] = None):
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        key = data.get("key")
    if not key:
        return jsonify({"ok": False, "message": "no key provided"}), 400
    return _validate_key_internal(key)

def _validate_key_internal(key: str):
    now = now_ts()
    # global override first
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

# ---------- Admin endpoints (preserve names) ----------
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
    if "duration_hours" in data:
        duration = int(data.get("duration_hours", 24)) * 3600
    else:
        duration = int(data.get("duration", 24 * 3600))
    did = data.get("did") or None
    if not key or len(str(key)) < 3:
        return jsonify({"ok": False, "message": "key too short"}), 400
    try:
        create_custom_key(key, did, duration)
        audit_log(session.get("user", {}).get("id"), "admin_generate_key", {"key": key, "did": did, "expires_at": int(time.time()) + duration})
        return jsonify({"ok": True, "key": key, "expires_at": int(time.time()) + duration}), 200
    except Exception:
        logger.exception("admin generate failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/keys", methods=["GET"])
def admin_api_list_keys():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    try:
        keys = list_all_keys()
        return jsonify({"keys": keys}), 200
    except Exception:
        logger.exception("admin list failed")
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
        logger.exception("admin revoke failed")
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
        duration = int(data.get("duration", 24 * 3600))
    if not id_:
        return jsonify({"ok": False, "message": "no id provided"}), 400
    expires_at = now_ts() + duration
    try:
        set_override(id_, expires_at)
        audit_log(session.get("user", {}).get("id"), "create_override", {"id": id_, "expires_at": expires_at})
        return jsonify({"ok": True, "id": id_, "expires_at": expires_at}), 200
    except Exception:
        logger.exception("admin override failed")
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
        logger.exception("admin overrides failed")
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
        logger.exception("admin audit failed")
        return jsonify({"ok": False, "message": "server error"}), 500

@app.route("/admin/api/validate_key", methods=["POST"])
def admin_api_validate_key():
    if not is_owner_session():
        return jsonify({"ok": False, "message": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    if not key:
        return jsonify({"ok": False, "message": "no key provided"}), 400
    return _validate_key_internal(key)

# ---------- Misc compatibility routes ----------
@app.route("/me", methods=["GET"])
def me_route():
    user = session.get("user") or {}
    return jsonify({"username": user.get("username"), "id": user.get("id"), "is_admin": bool(is_owner_session())}), 200

# Session debug (temporary — remove or protect in production)
@app.route("/_debug/session", methods=["GET"])
def _debug_session():
    data = {"session_keys": list(session.keys()), "session_user": session.get("user")}
    logger.debug("SESSION DEBUG: %s", json.dumps(data, default=str))
    return jsonify({"ok": True, "data": data}), 200

# ---------- Run (if executed directly) ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", os.environ.get("FLASK_RUN_PORT", 5000)))
    logger.info("Starting app on 0.0.0.0:%s", port)
    app.run(host="0.0.0.0", port=port)
