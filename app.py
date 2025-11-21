# app.py  -- Part 1 of 4 (reworked, full-featured, drop-in)
import os
import uuid
import json
import logging
import re
import time
import threading
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import importlib

import requests
from flask import Flask, request, g, jsonify, session, redirect, url_for

# --- Config loader ---------------------------------------------------------
class Config:
    def __init__(self):
        self.ENV = os.getenv("FLASK_ENV", "production")
        self.DEBUG = os.getenv("FLASK_DEBUG", "0") in ("1", "true", "True")
        self.SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
        self.DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
        self.DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
        self.DISCORD_REDIRECT = os.getenv("DISCORD_REDIRECT", "/login/discord/callback")
        self.DISCORD_API_BASE = os.getenv("DISCORD_API_BASE", "https://discord.com/api")
        self.ADMIN_USER_IDS = self._parse_int_list(os.getenv("ADMIN_USER_IDS", ""))
        self.ALLOW_CUSTOM_KEY = os.getenv("ALLOW_CUSTOM_KEY", "1") in ("1", "true", "True")
        self.LOG_FILE = os.getenv("LOG_FILE", "")
        self.GUNICORN_WORKERS = int(os.getenv("GUNICORN_WORKERS", "2"))
        
        # ✅ Session cookie settings
        self.SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "None")
        self.SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "1") in ("1", "true", "True")
        self.SESSION_COOKIE_DOMAIN = os.getenv("SESSION_COOKIE_DOMAIN", ".gaming-mods.com")
    @staticmethod
    def _parse_int_list(raw: str):
        if not raw:
            return []
        return [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]

# --- Logging setup --------------------------------------------------------
def make_logger(name: str = "yt_discord_verifier", logfile: str = "") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    cfg = Config()
    logger.setLevel(logging.DEBUG if cfg.DEBUG else logging.INFO)
    fmt = json.dumps({
        "time": "%(asctime)s",
        "level": "%(levelname)s",
        "name": "%(name)s",
        "req_id": "%(req_id)s",
        "msg": "%(message)s"
    })
    formatter = logging.Formatter(fmt)
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)
    if logfile:
        file_handler = RotatingFileHandler(logfile, maxBytes=10_000_000, backupCount=3)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    logger.propagate = False
    return logger

# --- Simple request-id middleware helpers ---------------------------------
def get_request_id() -> str:
    return getattr(g, "request_id", str(uuid.uuid4()))

# --- Flask factory --------------------------------------------------------
def create_app(config: Optional[Config] = None) -> Flask:
    cfg = config or Config()
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=cfg.SECRET_KEY,
        DEBUG=cfg.DEBUG,
        ENV=cfg.ENV,
        SESSION_COOKIE_SAMESITE=cfg.SESSION_COOKIE_SAMESITE,
        SESSION_COOKIE_SECURE=cfg.SESSION_COOKIE_SECURE
    )
    # attach cfg and logger
    app.cfg = cfg
    logger = make_logger(logfile=cfg.LOG_FILE)
    app.logger_custom = logger
CORS(app, supports_credentials=True, origins=["https://gaming-mods.com"])
    # request-id and logging
@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        return make_response('', 200)

    class ReqIdFilter(logging.Filter):
        def filter(self, rec):
            rec.req_id = getattr(g, "request_id", "-")
            return True
    logger.addFilter(ReqIdFilter())

    # error handlers
    @app.errorhandler(400)
    def bad_request(err):
        payload = {"ok": False, "error": "bad_request", "message": str(err)}
        logger.warning(json.dumps({"event": "http.400", "message": str(err)}))
        return jsonify(payload), 400

    @app.errorhandler(404)
    def not_found(err):
        payload = {"ok": False, "error": "not_found", "message": "not found"}
        logger.warning(json.dumps({"event": "http.404", "path": request.path}))
        return jsonify(payload), 404

    @app.errorhandler(Exception)
    def handle_exception(exc):
        logger.exception(json.dumps({
            "event": "exception",
            "exception": repr(exc),
            "path": request.path,
            "method": request.method
        }))
        payload = {"ok": False, "error": "internal_error", "message": "internal server error", "req_id": g.request_id}
        return jsonify(payload), 500

    return app

# module-level app for gunicorn
app = create_app()
# app.py  -- Part 2 of 4
# Exceptions and validators
class ValidationError(Exception):
    def __init__(self, message, errors=None):
        super(ValidationError, self).__init__(message)
        self.errors = errors or []

class AuthorizationError(Exception):
    pass

class NotFoundError(Exception):
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

# register exception handlers
def _register_exception_handlers(app: Flask):
    @app.errorhandler(ValidationError)
    def handle_validation(err):
        app.logger_custom.warning(json.dumps({"event": "validation_error", "message": str(err), "errors": getattr(err, "errors", [])}))
        return jsonify({"ok": False, "error": "validation_error", "message": str(err)}), 400

    @app.errorhandler(AuthorizationError)
    def handle_auth(err):
        app.logger_custom.warning(json.dumps({"event": "auth_error", "message": str(err)}))
        return jsonify({"ok": False, "error": "forbidden", "message": "not authorized"}), 403

    @app.errorhandler(NotFoundError)
    def handle_not_found(err):
        app.logger_custom.warning(json.dumps({"event": "not_found", "message": str(err)}))
        return jsonify({"ok": False, "error": "not_found", "message": str(err)}), 404

# attempt register now (app exists)
try:
    _register_exception_handlers(app)
except Exception:
    pass

# --- In-memory stores -----------------------------------------------------
_store_lock = threading.RLock()
_KEYS_STORE = {}
_OVERRIDES_AUDIT = []

def _generate_key_id() -> str:
    return f"key_{int(time.time()*1000)}"
# app.py  -- Part 3 of 4
# Override resolution and key flows
class Override:
    def __init__(self, resolved_duration: Optional[int], role_id: Optional[str], applied_by_admin: bool):
        self.resolved_duration = resolved_duration
        self.role_id = role_id
        self.applied_by_admin = applied_by_admin

def resolve_override(app: Flask, requester_id: str, requested_role: str, payload: dict) -> Override:
    cfg = app.cfg
    logger = app.logger_custom
    mode = payload.get("mode", "quick")
    is_admin = False
    try:
        rid = int(str(requester_id))
        is_admin = rid in cfg.ADMIN_USER_IDS
    except Exception:
        is_admin = False
    applied_by_admin = False
    resolved_duration = None
    if payload.get("admin_override", False):
        if not is_admin:
            raise AuthorizationError("admin_override requested by non-admin")
        applied_by_admin = True
        if payload.get("duration_minutes"):
            resolved_duration = int(payload["duration_minutes"])
    if mode == "custom" and not cfg.ALLOW_CUSTOM_KEY and not applied_by_admin:
        raise ValidationError("custom keys are disabled by server configuration")
    if resolved_duration is None:
        if mode == "quick":
            resolved_duration = 10
        else:
            resolved_duration = int(payload.get("duration_minutes") or 60)
    with _store_lock:
        _OVERRIDES_AUDIT.append({
            "timestamp": datetime.utcnow().isoformat(),
            "requester_id": requester_id,
            "requested_role": requested_role,
            "mode": mode,
            "admin_override": bool(payload.get("admin_override", False)),
            "applied_by_admin": applied_by_admin,
            "resolved_duration": resolved_duration
        })
    logger.info(json.dumps({
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
            record["key_id"] = _generate_key_id()
        record["created_at"] = datetime.utcnow().isoformat()
        _KEYS_STORE[record["key_id"]] = record
    return record

def quick_key_create(app: Flask, payload: dict) -> dict:
    if payload.get("mode") != "quick":
        raise ValidationError("quick_key_create called with non-quick mode")
    validated = validate_key_payload(payload)
    override = resolve_override(app, validated["user_id"] or "anonymous", validated["role_id"], validated)
    duration = override.resolved_duration
    record = {
        "type": "quick",
        "user_id": validated["user_id"],
        "role_id": override.role_id,
        "duration_minutes": duration,
        "applied_by_admin": override.applied_by_admin
    }
    stored = _store_key_record(record)
    app.logger_custom.info(json.dumps({
        "event": "key.created",
        "key_id": stored["key_id"],
        "type": "quick",
        "user_id": stored["user_id"]
    }))
    return {"ok": True, "key": stored}

def custom_key_create(app: Flask, payload: dict) -> dict:
    if payload.get("mode") != "custom":
        raise ValidationError("custom_key_create called with non-custom mode")
    validated = validate_key_payload(payload)
    override = resolve_override(app, validated["user_id"] or "anonymous", validated["role_id"], validated)
    duration = override.resolved_duration
    custom_key = payload.get("custom_key_string")
    if custom_key is not None:
        if not override.applied_by_admin:
            raise AuthorizationError("only admin may set custom key string")
        if not re.match(r"^[A-Za-z0-9\-_]{4,64}$", custom_key):
            raise ValidationError("custom_key_string invalid format; allowed A-Z a-z 0-9 - _ length 4-64")
        stored = _store_key_record({
            "type": "custom",
            "user_id": validated["user_id"],
            "role_id": override.role_id,
            "duration_minutes": duration,
            "applied_by_admin": override.applied_by_admin
        }, key_id=custom_key)
    else:
        stored = _store_key_record({
            "type": "custom",
            "user_id": validated["user_id"],
            "role_id": override.role_id,
            "duration_minutes": duration,
            "applied_by_admin": override.applied_by_admin
        })
    app.logger_custom.info(json.dumps({
        "event": "key.created",
        "key_id": stored["key_id"],
        "type": "custom",
        "user_id": stored["user_id"]
    }))
    return {"ok": True, "key": stored}

def list_keys() -> list:
    with _store_lock:
        return list(_KEYS_STORE.values())

def list_override_audit() -> list:
    with _store_lock:
        return list(_OVERRIDES_AUDIT)

# app.py  -- Part 4 replacement
# Routes, Discord OAuth handlers, and health/debug endpoints

def _is_admin(app: Flask, user_id: str) -> bool:
    try:
        uid = int(str(user_id))
        return uid in app.cfg.ADMIN_USER_IDS
    except Exception:
        return False

@app.route("/create-key", methods=["POST"])
def create_key_route():
    payload = request.get_json(silent=True) or {}
    try:
        normalized = validate_key_payload(payload)
    except ValidationError:
        raise
    if not normalized["user_id"]:
        normalized["user_id"] = request.headers.get("X-User-Id") or "anonymous"
    mode = normalized["mode"]
    if mode == "quick":
        result = quick_key_create(app, normalized)
    else:
        result = custom_key_create(app, normalized)
    return jsonify(result), 200

@app.route("/postback", methods=["POST"])
def postback_route():
    payload = request.get_json(silent=True) or {}
    validated = validate_postback_payload(payload)
    app.logger_custom.info(json.dumps({"event": "postback.received", "tx": validated["transaction_id"], "status": validated["status"]}))
    try:
        if validated["status"].lower() in ("completed", "success", "ok") and validated["user_id"]:
            create_payload = {
                "mode": "quick",
                "user_id": validated["user_id"],
                "role_id": validated["metadata"].get("role_id", "default_role"),
                "admin_override": False
            }
            quick_key_create(app, create_payload)
    except Exception as exc:
        app.logger_custom.warning(json.dumps({"event": "postback.processing_error", "tx": validated["transaction_id"], "error": repr(exc)}))
    return jsonify({"ok": True, "tx": validated["transaction_id"]}), 200

@app.route("/admin/keys", methods=["GET"])
def admin_list_keys():
    user_id = request.headers.get("X-User-Id")
    if not _is_admin(app, user_id):
        raise AuthorizationError("not admin")
    return jsonify({"ok": True, "keys": list_keys()}), 200

@app.route("/admin/overrides", methods=["GET"])
def admin_list_overrides():
    user_id = request.headers.get("X-User-Id")
    if not _is_admin(app, user_id):
        raise AuthorizationError("not admin")
    return jsonify({"ok": True, "overrides": list_override_audit()}), 200

# --- Discord OAuth2 login flow kept minimal and consistent with frontend expectations
OAUTH_STATE_KEY = "oauth2_state"

def _build_redirect_uri():
    base = os.getenv("BASE_URL") or request.url_root.rstrip('/')
    path = app.cfg.DISCORD_REDIRECT
    if path.startswith("http"):
        return path
    return base + path

@app.route("/login/discord")
def login_discord():
    state = uuid.uuid4().hex
    session[OAUTH_STATE_KEY] = state
    params = {
        "client_id": app.cfg.DISCORD_CLIENT_ID,
        "redirect_uri": _build_redirect_uri(),
        "response_type": "code",
        "scope": "identify email",
        "state": state,
    }
    url = f"{app.cfg.DISCORD_API_BASE}/oauth2/authorize?" + "&".join([f"{k}={requests.utils.requote_uri(str(v))}" for k, v in params.items()])
    return redirect(url)

@app.route("/login/discord/callback")
def login_discord_callback():
    error = request.args.get("error")
    if error:
        return jsonify({'ok': False, 'error': 'oauth_error', 'message': error}), 400
    code = request.args.get("code")
    state = request.args.get("state")
    saved_state = session.pop(OAUTH_STATE_KEY, None)
    if not code or not state or saved_state != state:
        return jsonify({'ok': False, 'error': 'invalid_state', 'message': 'State mismatch or missing code'}), 400
    token_url = f"{app.cfg.DISCORD_API_BASE}/oauth2/token"
    data = {
        'client_id': app.cfg.DISCORD_CLIENT_ID,
        'client_secret': app.cfg.DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': _build_redirect_uri(),
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        token_resp = requests.post(token_url, data=data, headers=headers, timeout=8)
        token_resp.raise_for_status()
        token_json = token_resp.json()
    except Exception as e:
        app.logger_custom.exception("Discord token exchange failed")
        return jsonify({'ok': False, 'error': 'token_exchange_failed', 'message': str(e)}), 502
    access_token = token_json.get('access_token')
    if not access_token:
        return jsonify({'ok': False, 'error': 'no_access_token', 'message': token_json}), 502
    try:
        user_resp = requests.get(f"{app.cfg.DISCORD_API_BASE}/users/@me",
                                 headers={'Authorization': f"Bearer {access_token}"}, timeout=8)
        user_resp.raise_for_status()
        user_json = user_resp.json()
    except Exception as e:
        app.logger_custom.exception("Discord user fetch failed")
        return jsonify({'ok': False, 'error': 'user_fetch_failed', 'message': str(e)}), 502
    # persist minimal user in session
    user_id = user_json.get('id')
    username = user_json.get('username')
    session['user'] = {'id': str(user_id), 'username': username, 'raw': user_json}
    # redirect to configured frontend after successful login
    next_url = session.pop('next', None) or "https://gaming-mods.com/"
    return redirect(next_url)

@app.route("/portal/me", methods=["GET"])
def portal_me():
    user = session.get('user')
    if not user:
        return jsonify({'ok': False, 'message': 'not authenticated'}), 401
    return jsonify({'ok': True, 'user': {'id': str(user.get('id')), 'username': user.get('username')}})

# health and debug
@app.route("/_health", methods=["GET"])
def _health():
    return jsonify({"ok": True, "status": "healthy", "req_id": getattr(g, "request_id", None)}), 200

@app.route("/health", methods=["GET"])
def health_alias():
    return jsonify({"ok": True, "status": "healthy", "req_id": getattr(g, "request_id", None)}), 200

@app.route('/__debug_me')
def __debug_me():
    return jsonify({
        'ok': True,
        'pid': os.getpid(),
        'file': __file__,
        'env': {
            'DISCORD_CLIENT_ID': bool(os.getenv('DISCORD_CLIENT_ID')),
            'DISCORD_CLIENT_SECRET': bool(os.getenv('DISCORD_CLIENT_SECRET')),
            'DISCORD_REDIRECT': bool(os.getenv('DISCORD_REDIRECT'))
        }
    })

# ensure exception handlers registered at module import
try:
    _register_exception_handlers(app)
except Exception:
    pass

@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        return make_response('', 200)

# run for local debug
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=app.config.get("DEBUG", False))
