# app.py
"""
Full replacement Flask app with CORS credentials fixed and robust features:
- Single CORS configuration with supports_credentials=True
- After-request header enforcement for Access-Control-Allow-Credentials
- Auth (signup/login/forgot/reset) with bcrypt + JWT
- /portal/me with admin detection
- Admin decorator and admin endpoints
- In-memory key system (create/validate/burn)
- create-key GET/POST flows (browser + API)
- postback webhook handling
- Discord OAuth handlers (minimal)
- Health & debug endpoints
- Robust DB handling (returns JSON errors if DB unreachable)
"""

import os
import json
import uuid
import time
import secrets
import string
import logging
import threading
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Any
from urllib.parse import urlencode, unquote_plus

import requests
from flask import Flask, request, jsonify, g, session, redirect, render_template, make_response
from flask_cors import CORS
import mysql.connector
import bcrypt
import jwt

# -------------------------
# Configuration / Defaults
# -------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-super-secret")
MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "karim")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "Kmrykmry@4!Strong")
MYSQL_DB = os.getenv("MYSQL_DB", "verifier")
ADMIN_USER_IDS = [int(x) for x in os.getenv("ADMIN_USER_IDS", "").split(",") if x.strip().isdigit()]
CORS_ORIGINS = [
    "https://gaming-mods.com",
    "https://verifier.gaming-mods.com"
]
JWT_ALGO = "HS256"
JWT_EXP_HOURS = int(os.getenv("JWT_EXP_HOURS", "12"))
DEBUG = os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
LOG_FILE = os.getenv("LOG_FILE", "")

# Discord OAuth config (optional)
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT = os.getenv("DISCORD_REDIRECT", "https://verifier.gaming-mods.com/login/discord/callback")
DISCORD_API_BASE = os.getenv("DISCORD_API_BASE", "https://discord.com/api")

# -------------------------
# Logger (safe formatting)
# -------------------------
def make_logger(name: str = "verifier", logfile: str = "") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
    fmt = '{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","req_id":"%(req_id)s","msg":"%(message)s"}'
    class SafeFormatter(logging.Formatter):
        def format(self, record):
            if not hasattr(record, "req_id"):
                record.req_id = "-"
            return super().format(record)
    formatter = SafeFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    logger.addHandler(sh)
    if logfile:
        fh = RotatingFileHandler(logfile, maxBytes=10_000_000, backupCount=3)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    logger.propagate = False
    return logger

logger = make_logger("verifier", LOG_FILE)

# -------------------------
# App factory
# -------------------------
def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.update({
        "SECRET_KEY": SECRET_KEY,
        "DEBUG": DEBUG,
        # Session cookie settings (useful if you set cookies from this domain)
        "SESSION_COOKIE_SAMESITE": os.getenv("SESSION_COOKIE_SAMESITE", "Lax"),
        "SESSION_COOKIE_SECURE": str(os.getenv("SESSION_COOKIE_SECURE", "1")).lower() in ("1", "true", "yes"),
        "SESSION_COOKIE_DOMAIN": os.getenv("SESSION_COOKIE_DOMAIN", ".gaming-mods.com"),
        "SESSION_COOKIE_HTTPONLY": True,
    })

    # Single CORS call with credentials support
    CORS(app,
         resources={r"/*": {"origins": CORS_ORIGINS,
                            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
                            "expose_headers": ["Content-Type", "Authorization"],
                            }},
         supports_credentials=True)

    # request id middleware
    @app.before_request
    def assign_request_id():
        g.request_id = str(uuid.uuid4())

    # attach logger with req_id filter
    class ReqIdFilter(logging.Filter):
        def filter(self, rec):
            rec.req_id = getattr(g, "request_id", "-")
            return True
    req_filter = ReqIdFilter()
    logger.addFilter(req_filter)
    app.logger.addFilter(req_filter)
    app.logger_custom = logger

    # Ensure Access-Control-Allow-Credentials header is present and true for credentialed requests
    @app.after_request
    def ensure_cors_credentials(response):
        # If the request included credentials (cookies or Authorization), ensure header is 'true'
        # Always set to 'true' to satisfy browsers when credentials mode is 'include'
        response.headers["Access-Control-Allow-Credentials"] = "true"
        # When using credentials, Access-Control-Allow-Origin must not be '*'.
        # flask-cors will set the origin header; ensure it's present or echo the request origin.
        if "Access-Control-Allow-Origin" not in response.headers or response.headers.get("Access-Control-Allow-Origin") == "":
            origin = request.headers.get("Origin")
            if origin and origin in CORS_ORIGINS:
                response.headers["Access-Control-Allow-Origin"] = origin
        return response

    # error handlers
    @app.errorhandler(400)
    def _bad_request(e):
        logger.warning(json.dumps({"event":"http.400","path": request.path, "msg": str(e)}))
        return jsonify({"ok": False, "error": "bad_request", "message": str(e)}), 400

    @app.errorhandler(404)
    def _not_found(e):
        logger.warning(json.dumps({"event":"http.404","path": request.path}))
        return jsonify({"ok": False, "error": "not_found", "message": "not found"}), 404

    @app.errorhandler(Exception)
    def _handle_exc(e):
        logger.exception(json.dumps({"event":"exception","path": request.path, "method": request.method, "exception": repr(e)}))
        return jsonify({"ok": False, "error": "internal_error", "message": "internal server error", "req_id": getattr(g, "request_id", None)}), 500

    return app

app = create_app()

# -------------------------
# DB helper (returns None on failure)
# -------------------------
def get_db():
    try:
        conn = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST", MYSQL_HOST),
            port=int(os.getenv("MYSQL_PORT", MYSQL_PORT)),
            user=os.getenv("MYSQL_USER", MYSQL_USER),
            password=os.getenv("MYSQL_PASSWORD", MYSQL_PASSWORD),
            database=os.getenv("MYSQL_DB", MYSQL_DB),
            connection_timeout=5,
        )
        return conn
    except Exception as e:
        try:
            app.logger_custom.error(f"DB connect error: {e}")
        except Exception:
            print("DB connect error:", e)
        return None

# -------------------------
# Utilities
# -------------------------
def jwt_encode(payload: dict) -> str:
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)

def jwt_decode(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return plain == hashed

def generate_random_key(length=10) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# -------------------------
# In-memory key store (thread-safe)
# -------------------------
_store_lock = threading.RLock()
_KEYS_STORE: Dict[str, dict] = {}
_OVERRIDES_AUDIT = []
global_override = False
admin_overrides = {}
LEGACY_LIMIT_SECONDS = 3600

# -------------------------
# Decorators
# -------------------------
def require_admin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error": "missing_token"}), 403
        token = auth.split(" ", 1)[1]
        try:
            payload = jwt_decode(token)
        except Exception:
            return jsonify({"error": "invalid_token"}), 403
        user_id = payload.get("user_id")
        if not user_id:
            return jsonify({"error": "invalid_payload"}), 403
        db = get_db()
        if db is None:
            return jsonify({"error": "db_connection_failed"}), 500
        try:
            cur = db.cursor(dictionary=True)
            cur.execute("SELECT id, role FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
        finally:
            try: cur.close()
            except: pass
            try: db.close()
            except: pass
        if not user:
            return jsonify({"error": "user_not_found"}), 403
        if user.get("role") != "admin":
            return jsonify({"error": "not_admin"}), 403
        g.admin_id = user["id"]
        return f(*args, **kwargs)
    return wrapped

# -------------------------
# Validation helpers
# -------------------------
class ValidationError(Exception):
    pass

def _ensure_str(value, name):
    if value is None:
        raise ValidationError(f"{name} is required")
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a string")
    val = value.strip()
    if not val:
        raise ValidationError(f"{name} must not be empty")
    return val

def _ensure_int(value, name, minimum=None, maximum=None):
    if value is None or value == "":
        raise ValidationError(f"{name} is required")
    try:
        iv = int(value)
    except Exception:
        raise ValidationError(f"{name} must be an integer")
    if minimum is not None and iv < minimum:
        raise ValidationError(f"{name} must be >= {minimum}")
    if maximum is not None and iv > maximum:
        raise ValidationError(f"{name} must be <= {maximum}")
    return iv

def _ensure_bool_like(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return value.lower() in ("1", "true", "yes", "y")
    return bool(value)

def validate_key_payload(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValidationError("payload must be a JSON object")
    mode = data.get("mode", "quick")
    mode = _ensure_str(mode, "mode").lower()
    if mode not in ("quick", "custom"):
        raise ValidationError("mode must be 'quick' or 'custom'")
    user_id_raw = data.get("user_id")
    user_id = _ensure_str(str(user_id_raw), "user_id") if user_id_raw is not None else ""
    role_id_raw = data.get("role_id")
    role_id = _ensure_str(str(role_id_raw), "role_id") if role_id_raw is not None else "default_role"
    admin_override = _ensure_bool_like(data.get("admin_override", False))
    duration_minutes = None
    if mode == "custom":
        duration_raw = data.get("duration_minutes")
        duration_minutes = _ensure_int(duration_raw, "duration_minutes", minimum=1, maximum=60*24*30)
    elif mode == "quick":
        dur = data.get("duration_minutes")
        if dur is not None and dur != "":
            duration_minutes = _ensure_int(dur, "duration_minutes", minimum=1, maximum=60*24*30)
    return {
        "mode": mode,
        "user_id": user_id,
        "role_id": role_id,
        "admin_override": admin_override,
        "duration_minutes": duration_minutes
    }

def validate_postback_payload(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValidationError("postback payload must be a JSON object")
    tx_id = data.get("transaction_id") or data.get("tx") or data.get("id")
    if tx_id is None:
        tx_id = f"tx-{int(datetime.utcnow().timestamp())}"
    tx_id = _ensure_str(str(tx_id), "transaction_id")
    user_id_raw = data.get("user_id") or data.get("uid")
    user_id = _ensure_str(str(user_id_raw), "user_id") if user_id_raw is not None else None
    status = data.get("status", "unknown")
    status = _ensure_str(status, "status")
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {"raw": str(metadata)}
    return {
        "transaction_id": tx_id,
        "user_id": user_id,
        "status": status,
        "metadata": metadata
    }

# -------------------------
# Key flows
# -------------------------
class Override:
    def __init__(self, resolved_duration: Optional[int], role_id: Optional[str], applied_by_admin: bool):
        self.resolved_duration = resolved_duration
        self.role_id = role_id
        self.applied_by_admin = applied_by_admin

def resolve_override(app_obj, requester_id: str, requested_role: str, payload: dict) -> Override:
    cfg_admin_ids = app_obj.cfg.ADMIN_USER_IDS if hasattr(app_obj, "cfg") else ADMIN_USER_IDS
    is_admin = False
    try:
        rid = int(str(requester_id))
        is_admin = rid in cfg_admin_ids
    except Exception:
        is_admin = False

    applied_by_admin = False
    resolved_duration = None

    if payload.get("admin_override", False):
        if not is_admin:
            raise ValidationError("admin_override requested by non-admin")
        applied_by_admin = True
        if payload.get("duration_minutes"):
            resolved_duration = int(payload["duration_minutes"])

    if resolved_duration is None:
        if payload.get("mode") == "quick":
            resolved_duration = 10
        else:
            resolved_duration = int(payload.get("duration_minutes") or 60)

    with _store_lock:
        _OVERRIDES_AUDIT.append({
            "timestamp": datetime.utcnow().isoformat(),
            "requester_id": requester_id,
            "requested_role": requested_role,
            "mode": payload.get("mode"),
            "admin_override": bool(payload.get("admin_override", False)),
            "applied_by_admin": applied_by_admin,
            "resolved_duration": resolved_duration
        })

    app.logger_custom.info(json.dumps({
        "event": "override.resolved",
        "requester_id": requester_id,
        "role": requested_role,
        "duration": resolved_duration,
        "admin": applied_by_admin
    }))
    return Override(resolved_duration=resolved_duration, role_id=requested_role, applied_by_admin=applied_by_admin)

def _store_key_record(record: dict, key_id: Optional[str] = None) -> dict:
    with _store_lock:
        if key_id:
            if key_id in _KEYS_STORE:
                raise ValidationError("custom key string already exists")
            record["key_id"] = key_id
        else:
            record["key_id"] = generate_random_key(10)
        record.setdefault("status", "active")
        record["created_at"] = datetime.utcnow().isoformat()
        _KEYS_STORE[record["key_id"]] = record
        return _KEYS_STORE[record["key_id"]]

def quick_key_create(app_obj, payload: dict) -> dict:
    validated = validate_key_payload(payload)
    override = resolve_override(app_obj, validated["user_id"] or "anonymous", validated["role_id"], validated)
    duration = override.resolved_duration
    record = {
        "type": "quick",
        "user_id": validated["user_id"],
        "role_id": override.role_id,
        "duration_minutes": duration,
        "applied_by_admin": override.applied_by_admin,
        "status": "active",
        "created_at": datetime.utcnow().isoformat()
    }
    record["expires_at"] = float(time.time() + duration * 60)
    record["expiry_iso"] = datetime.utcfromtimestamp(record["expires_at"]).isoformat()
    stored = _store_key_record(record)
    app.logger_custom.info(json.dumps({"event":"key.created","key_id": stored["key_id"], "user_id": stored["user_id"]}))
    return {"ok": True, "key": stored}

def custom_key_create(app_obj, payload: dict) -> dict:
    validated = validate_key_payload(payload)
    override = resolve_override(app_obj, validated["user_id"] or "anonymous", validated["role_id"], validated)
    duration = override.resolved_duration
    custom_key = payload.get("custom_key_string")
    base_record = {
        "type": "custom",
        "user_id": validated["user_id"],
        "role_id": override.role_id,
        "duration_minutes": duration,
        "applied_by_admin": override.applied_by_admin,
        "status": "active",
        "created_at": datetime.utcnow().isoformat()
    }
    base_record["expires_at"] = float(time.time() + duration * 60)
    base_record["expiry_iso"] = datetime.utcfromtimestamp(base_record["expires_at"]).isoformat()
    if custom_key is not None:
        if not override.applied_by_admin:
            raise ValidationError("only admin may set custom key string")
        if not isinstance(custom_key, str) or not custom_key or len(custom_key) < 4:
            raise ValidationError("custom_key_string invalid")
        stored = _store_key_record(base_record, key_id=custom_key)
    else:
        stored = _store_key_record(base_record)
    app.logger_custom.info(json.dumps({"event":"key.created","key_id": stored["key_id"], "user_id": stored["user_id"]}))
    return {"ok": True, "key": stored}

def list_keys() -> list:
    with _store_lock:
        return list(_KEYS_STORE.values())

# -------------------------
# Routes: Auth
# -------------------------
@app.post("/auth/signup")
def auth_signup():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"error": "missing_fields"}), 400
    db = get_db()
    if db is None:
        return jsonify({"error": "db_connection_failed"}), 500
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({"error": "email_exists"}), 409
        pw_hash = hash_password(password)
        cur.execute("INSERT INTO users (email, password_hash, role, created_at) VALUES (%s, %s, %s, %s)", (email, pw_hash, "user", datetime.utcnow()))
        db.commit()
        return jsonify({"ok": True}), 201
    finally:
        try: cur.close()
        except: pass
        try: db.close()
        except: pass

@app.post("/auth/login")
def auth_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"error": "missing_fields"}), 400
    db = get_db()
    if db is None:
        return jsonify({"error": "db_connection_failed"}), 500
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id, password_hash, role FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if not user:
            return jsonify({"error": "not_found"}), 404
        stored = user.get("password_hash") or ""
        if not check_password(password, stored):
            return jsonify({"error": "invalid_password"}), 403
        payload = {"user_id": user["id"], "role": user.get("role", "user"), "exp": datetime.utcnow() + timedelta(hours=JWT_EXP_HOURS)}
        token = jwt_encode(payload)
        return jsonify({"token": token})
    finally:
        try: cur.close()
        except: pass
        try: db.close()
        except: pass

@app.post("/auth/forgot")
def auth_forgot():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "missing_email"}), 400
    db = get_db()
    if db is None:
        return jsonify({"error": "db_connection_failed"}), 500
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if not user:
            return jsonify({"ok": True})
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=1)
        cur.execute("UPDATE users SET reset_token=%s, reset_expires=%s WHERE id = %s", (token, expires, user["id"]))
        db.commit()
        app.logger_custom.info(json.dumps({"event":"password.reset.requested","email": email}))
        print("RESET LINK:", f"https://gaming-mods.com/reset?token={token}")
        return jsonify({"ok": True})
    finally:
        try: cur.close()
        except: pass
        try: db.close()
        except: pass

@app.post("/auth/reset")
def auth_reset():
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    new_password = data.get("password")
    if not token or not new_password:
        return jsonify({"error": "missing_fields"}), 400
    db = get_db()
    if db is None:
        return jsonify({"error": "db_connection_failed"}), 500
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id FROM users WHERE reset_token = %s AND reset_expires > NOW()", (token,))
        user = cur.fetchone()
        if not user:
            return jsonify({"error": "invalid_token"}), 400
        pw_hash = hash_password(new_password)
        cur.execute("UPDATE users SET password_hash=%s, reset_token=NULL, reset_expires=NULL WHERE id=%s", (pw_hash, user["id"]))
        db.commit()
        return jsonify({"ok": True})
    finally:
        try: cur.close()
        except: pass
        try: db.close()
        except: pass

# -------------------------
# Portal /me (detect admin)
# -------------------------
@app.get("/portal/me")
def portal_me():
    auth = request.headers.get("Authorization", "")
    if not auth or not auth.startswith("Bearer "):
        return jsonify({"error": "missing_token"}), 401
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt_decode(token)
    except Exception:
        return jsonify({"error": "invalid_token"}), 401
    user_id = payload.get("user_id")
    if not user_id:
        return jsonify({"error": "invalid_payload"}), 401
    db = get_db()
    if db is None:
        return jsonify({"error": "db_connection_failed"}), 500
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id, email, username, role FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({"error": "user_not_found"}), 404
        user["is_admin"] = (user.get("role") == "admin")
        return jsonify({"ok": True, "user": user})
    finally:
        try: cur.close()
        except: pass
        try: db.close()
        except: pass

# -------------------------
# Admin endpoints (examples)
# -------------------------
@app.get("/admin/logs")
@require_admin
def admin_logs():
    return jsonify({"logs": _OVERRIDES_AUDIT[-200:]}), 200

@app.post("/admin/add-perk")
@require_admin
def admin_add_perk():
    data = request.get_json(silent=True) or {}
    perk = data.get("perk")
    if not perk:
        return jsonify({"error": "missing_perk"}), 400
    db = get_db()
    if db is None:
        return jsonify({"error": "db_connection_failed"}), 500
    try:
        cur = db.cursor()
        cur.execute("INSERT INTO perks (name, description) VALUES (%s, %s)", (perk, ""))
        db.commit()
        cur.execute("INSERT INTO admin_logs (admin_id, action_type, details) VALUES (%s, %s, %s)", (g.admin_id, "add_perk", f"Added perk {perk}"))
        db.commit()
        return jsonify({"status": "success", "action": f"Added perk {perk}"})
    finally:
        try: cur.close()
        except: pass
        try: db.close()
        except: pass

@app.post("/admin/remove-perk")
@require_admin
def admin_remove_perk():
    data = request.get_json(silent=True) or {}
    perk = data.get("perk")
    if not perk:
        return jsonify({"error": "missing_perk"}), 400
    db = get_db()
    if db is None:
        return jsonify({"error": "db_connection_failed"}), 500
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id FROM perks WHERE name = %s", (perk,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "perk_not_found"}), 404
        perk_id = row["id"]
        cur2 = db.cursor()
        cur2.execute("DELETE FROM perks WHERE id = %s", (perk_id,))
        db.commit()
        cur2.execute("INSERT INTO admin_logs (admin_id, action_type, details) VALUES (%s, %s, %s)", (g.admin_id, "remove_perk", f"Removed perk {perk}"))
        db.commit()
        return jsonify({"status": "success", "action": f"Removed perk {perk}"})
    finally:
        try: cur.close()
        except: pass
        try: cur2.close()
        except: pass
        try: db.close()
        except: pass

@app.post("/admin/ban-user")
@require_admin
def admin_ban_user():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "missing_user_id"}), 400
    db = get_db()
    if db is None:
        return jsonify({"error": "db_connection_failed"}), 500
    try:
        cur = db.cursor()
        cur.execute("UPDATE users SET banned = 1 WHERE id = %s", (user_id,))
        db.commit()
        cur.execute("INSERT INTO admin_logs (admin_id, action_type, details, target_user_id) VALUES (%s, %s, %s, %s)", (g.admin_id, "ban_user", f"Banned user {user_id}", user_id))
        db.commit()
        return jsonify({"status": "success", "action": f"Banned user {user_id}"})
    finally:
        try: cur.close()
        except: pass
        try: db.close()
        except: pass

# -------------------------
# Key management (public)
# -------------------------
@app.post("/create-key")
def create_key_api():
    payload = request.get_json(silent=True) or {}
    try:
        normalized = validate_key_payload(payload)
    except ValidationError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    if not normalized.get("user_id"):
        normalized["user_id"] = request.headers.get("X-User-Id") or "anonymous"
    mode = normalized.get("mode", "quick")
    if mode == "quick":
        created = quick_key_create(app, normalized)
    else:
        created = custom_key_create(app, normalized)
    record = created.get("key", {})
    with _store_lock:
        _KEYS_STORE[record["key_id"]] = record
    return jsonify({"ok": True, "key": record}), 200

@app.get("/validate_key/<path:key_to_validate>")
def validate_key_route(key_to_validate):
    key_to_validate = unquote_plus(str(key_to_validate)).strip()
    now = time.time()
    with _store_lock:
        rec = _KEYS_STORE.get(key_to_validate)
    if not rec:
        return jsonify({"ok": False, "valid": False, "message": "Invalid or unknown key"}), 400
    try:
        rec_expires_at = float(rec.get("expires_at") or 0)
    except Exception:
        return jsonify({"ok": False, "valid": False, "message": "Malformed expiry"}), 500
    if now > rec_expires_at:
        with _store_lock:
            rec["status"] = "revoked"
            _KEYS_STORE[key_to_validate] = rec
        return jsonify({"ok": False, "valid": False, "message": "Key expired"}), 410
    valid = rec.get("status") == "active"
    return jsonify({"ok": True, "valid": valid, "message": "Key valid" if valid else "Key revoked", "expires_at": rec_expires_at, "expires_in": int(rec_expires_at - now)}), 200

@app.post("/keys/burn")
def keys_burn():
    data = request.get_json(silent=True) or {}
    key_to_burn = data.get("key")
    if not key_to_burn:
        return jsonify({"ok": False, "message": "No key provided"}), 400
    with _store_lock:
        key_info = _KEYS_STORE.get(key_to_burn)
        if not key_info:
            return jsonify({"ok": False, "message": "Key not found"}), 404
        key_info["status"] = "revoked"
        _KEYS_STORE[key_to_burn] = key_info
    app.logger_custom.info(json.dumps({"event":"key.burned","key_id": key_to_burn, "user_id": key_info.get("user_id")}))
    return jsonify({"ok": True, "message": f"Key {key_to_burn} burned"}), 200

@app.route("/create-key", methods=["GET"])
def create_key_get():
    user_id = session.get("user", {}).get("id") if session else None
    user_id = str(user_id) if user_id else request.args.get("user_id") or "anonymous"
    payload = {"mode": "quick", "user_id": user_id}
    created = quick_key_create(app, payload)
    record = created.get("key", {})
    with _store_lock:
        _KEYS_STORE[record["key_id"]] = record
    return redirect("https://gaming-mods.com/keys.html")

# -------------------------
# Postback webhook
# -------------------------
@app.post("/postback")
def postback_route():
    payload = request.get_json(silent=True) or {}
    try:
        validated = validate_postback_payload(payload)
    except ValidationError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    app.logger_custom.info(json.dumps({"event":"postback.received","tx": validated["transaction_id"], "status": validated["status"]}))
    try:
        if validated["status"].lower() in ("completed", "success", "ok") and validated["user_id"]:
            create_payload = {"mode": "quick", "user_id": validated["user_id"], "role_id": validated["metadata"].get("role_id", "default_role"), "admin_override": False}
            created = quick_key_create(app, create_payload)
            record = created.get("key", {})
            with _store_lock:
                _KEYS_STORE[record["key_id"]] = record
    except Exception as exc:
        app.logger_custom.warning(json.dumps({"event":"postback.processing_error","tx": validated.get("transaction_id"), "error": repr(exc)}))
    return jsonify({"ok": True, "tx": validated.get("transaction_id")}), 200

# -------------------------
# Admin list keys / overrides (header-based simple admin)
# -------------------------
def _is_admin_header(user_id_header: Optional[str]) -> bool:
    try:
        return int(str(user_id_header)) in ADMIN_USER_IDS
    except Exception:
        return False

@app.get("/admin/keys")
def admin_list_keys():
    user_id = request.headers.get("X-User-Id")
    if not _is_admin_header(user_id):
        return jsonify({"error": "not_admin"}), 403
    return jsonify({"ok": True, "keys": list_keys()}), 200

@app.get("/admin/overrides")
def admin_list_overrides():
    user_id = request.headers.get("X-User-Id")
    if not _is_admin_header(user_id):
        return jsonify({"error": "not_admin"}), 403
    return jsonify({"ok": True, "overrides": _OVERRIDES_AUDIT}), 200

# -------------------------
# Discord OAuth (minimal)
# -------------------------
def exchange_token_with_backoff(token_url, data, headers):
    resp = requests.post(token_url, data=data, headers=headers, timeout=8)
    if resp.status_code == 429:
        return {"error": "rate_limited"}
    resp.raise_for_status()
    return resp.json()

@app.get("/login/discord")
def discord_login():
    if not DISCORD_CLIENT_ID:
        return jsonify({"error": "discord_not_configured"}), 500
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT,
        "response_type": "code",
        "scope": "identify email"
    }
    return redirect(f"{DISCORD_API_BASE}/oauth2/authorize?{urlencode(params)}")

@app.get("/login/discord/callback")
def discord_callback():
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "missing_code"}), 400
    token_url = f"{DISCORD_API_BASE}/oauth2/token"
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        token_resp = exchange_token_with_backoff(token_url, data, headers)
        if token_resp.get("error"):
            return jsonify({"error": "token_exchange_failed", "detail": token_resp}), 500
        access_token = token_resp.get("access_token")
        user_resp = requests.get(f"{DISCORD_API_BASE}/users/@me", headers={"Authorization": f"Bearer {access_token}"}, timeout=8)
        user_resp.raise_for_status()
        user_info = user_resp.json()
        db = get_db()
        if db:
            try:
                cur = db.cursor(dictionary=True)
                email = user_info.get("email")
                discord_id = user_info.get("id")
                cur.execute("SELECT id FROM users WHERE discord_id = %s OR email = %s", (discord_id, email))
                row = cur.fetchone()
                if row:
                    user_id = row["id"]
                else:
                    cur.execute("INSERT INTO users (email, username, discord_id, role, created_at) VALUES (%s, %s, %s, %s, %s)", (email, user_info.get("username"), discord_id, "user", datetime.utcnow()))
                    db.commit()
                    user_id = cur.lastrowid
                payload = {"user_id": user_id, "role": "user", "exp": datetime.utcnow() + timedelta(hours=JWT_EXP_HOURS)}
                token = jwt_encode(payload)
                session["user"] = {"id": user_id, "username": user_info.get("username")}
                return redirect(f"https://gaming-mods.com/?token={token}")
            finally:
                try: cur.close()
                except: pass
                try: db.close()
                except: pass
        else:
            return jsonify({"ok": True, "user_info": user_info, "note": "db_unavailable"}), 200
    except Exception as e:
        app.logger_custom.exception("Discord callback failed: %s", e)
        return jsonify({"error": "discord_callback_failed", "detail": str(e)}), 500

# -------------------------
# Health & Debug
# -------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True, "status": "healthy", "req_id": getattr(g, "request_id", None)}), 200

@app.get("/__debug_me")
def debug_me():
    cfg = {
        "SECRET_KEY_set": bool(os.getenv("SECRET_KEY")),
        "MYSQL_HOST": os.getenv("MYSQL_HOST"),
        "MYSQL_DB": os.getenv("MYSQL_DB"),
        "ADMIN_USER_IDS": ADMIN_USER_IDS,
        "DEBUG": DEBUG
    }
    return jsonify({"ok": True, "pid": os.getpid() if hasattr(os, "getpid") else None, "cfg": cfg, "req_id": getattr(g, "request_id", None)}), 200

# -------------------------
# Root redirect
# -------------------------
@app.get("/")
def index():
    return redirect("https://gaming-mods.com")

# -------------------------
# Run (for local dev)
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=DEBUG)
