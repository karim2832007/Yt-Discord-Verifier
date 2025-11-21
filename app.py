# app.py  -- Part 1 of 4
import os
import uuid
import json
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, Any

from flask import Flask, request, g, jsonify

# --- Config loader ---------------------------------------------------------
class Config:
    """
    Minimal typed config loader for environment-driven settings.
    """
    def __init__(self):
        self.ENV = os.getenv("FLASK_ENV", "production")
        self.DEBUG = os.getenv("FLASK_DEBUG", "0") in ("1", "true", "True")
        self.SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
        self.DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
        self.ADMIN_USER_IDS = self._parse_int_list(os.getenv("ADMIN_USER_IDS", ""))
        self.ALLOW_CUSTOM_KEY = os.getenv("ALLOW_CUSTOM_KEY", "1") in ("1", "true", "True")
        self.LOG_FILE = os.getenv("LOG_FILE", "")
        self.GUNICORN_WORKERS = int(os.getenv("GUNICORN_WORKERS", "2"))

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
    logger.setLevel(logging.DEBUG if Config().DEBUG else logging.INFO)

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

    # prevent Flask from adding duplicate handlers
    logger.propagate = False
    return logger

# --- Simple request-id middleware helpers ---------------------------------
def get_request_id() -> str:
    return getattr(g, "request_id", str(uuid.uuid4()))

def attach_req_id_record(record):
    record.req_id = get_request_id()
    return True

# --- Flask factory --------------------------------------------------------
def create_app(config: Optional[Config] = None) -> Flask:
    cfg = config or Config()
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=cfg.SECRET_KEY,
        DEBUG=cfg.DEBUG,
        ENV=cfg.ENV
    )

    # logger
    logger = make_logger(logfile=cfg.LOG_FILE)
    logging.Logger.addFilter = logging.Logger.addFilter  # defensive no-op binding
    # attach request id to all log records via filter
    class ReqIdFilter(logging.Filter):
        def filter(self, rec):
            rec.req_id = getattr(g, "request_id", "-")
            return True
    logger.addFilter(ReqIdFilter())

    # request-id before request
    @app.before_request
    def assign_request_id():
        g.request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        logger.info(json.dumps({
            "event": "request.start",
            "method": request.method,
            "path": request.path,
            "remote_addr": request.remote_addr
        }))

    # attach logger to app for convenient access in other parts
    app.logger_custom = logger
    app.cfg = cfg

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
        # general exception catcher that returns JSON and logs detailed info
        logger.exception(json.dumps({
            "event": "exception",
            "exception": repr(exc),
            "path": request.path,
            "method": request.method
        }))
        payload = {"ok": False, "error": "internal_error", "message": "internal server error", "req_id": g.request_id}
        return jsonify(payload), 500

    return app

# convenience top-level app for gunicorn
app = create_app()

# app.py  -- Part 2 of 4
import re
from datetime import datetime, timedelta

# --- Exceptions ------------------------------------------------------------
class ValidationError(Exception):
    def __init__(self, message, errors=None):
        super(ValidationError, self).__init__(message)
        self.errors = errors or []

class AuthorizationError(Exception):
    pass

class NotFoundError(Exception):
    pass

# --- Simple validators -----------------------------------------------------
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

# Key creation payload validator
def validate_key_payload(data: dict) -> dict:
    """
    Expected keys:
      - mode: "quick" or "custom" (optional, default "quick")
      - user_id: string/int identifying the requester
      - duration_minutes: required for custom mode; integer
      - role_id: id of the discord role to grant (string)
      - admin_override: optional bool-like
    Returns normalized dict or raises ValidationError.
    """
    if not isinstance(data, dict):
        raise ValidationError("payload must be a JSON object")
    mode = data.get("mode", "quick")
    mode = _ensure_str(mode, "mode").lower()
    if mode not in ("quick", "custom"):
        raise ValidationError("mode must be 'quick' or 'custom'")
    user_id_raw = data.get("user_id")
    user_id = _ensure_str(str(user_id_raw), "user_id")

    role_id_raw = data.get("role_id")
    role_id = _ensure_str(str(role_id_raw), "role_id")

    admin_override = _ensure_bool_like(data.get("admin_override", False))

    duration_minutes = None
    if mode == "custom":
        duration_raw = data.get("duration_minutes")
        duration_minutes = _ensure_int(duration_raw, "duration_minutes", minimum=1, maximum=60*24*30)
    elif mode == "quick":
        # quick mode may optionally accept a duration, but it's ignored by quick generator
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

# Postback payload validator (tolerant)
def validate_postback_payload(data: dict) -> dict:
    """
    Expected keys from external services. Be tolerant:
      - transaction_id (preferred)
      - user_id
      - status
      - metadata (optional dict)
    Missing non-critical keys tolerated; validation will coerce types where possible.
    """
    if not isinstance(data, dict):
        raise ValidationError("postback payload must be a JSON object")
    tx_id = data.get("transaction_id") or data.get("tx") or data.get("id")
    if tx_id is None:
        tx_id = f"tx-{int(datetime.utcnow().timestamp())}"
    tx_id = _ensure_str(str(tx_id), "transaction_id")

    user_id_raw = data.get("user_id") or data.get("uid")
    if user_id_raw is None:
        user_id = None
    else:
        user_id = _ensure_str(str(user_id_raw), "user_id")

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

# --- Register exception handlers into app created earlier ------------------
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

# Immediately register handlers if app exists in this module (true when using single-file)
try:
    _register_exception_handlers(app)
except Exception:
    # create_app not yet run; handlers will be registered when create_app invoked in next part
    pass

# app.py  -- Part 3 of 4
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

# --- In-memory stores (replace with DB in production) ---------------------
# thread-safe simple stores for demo and tests
_store_lock = threading.RLock()
_KEYS_STORE = {}         # key_id -> key record
_OVERRIDES_AUDIT = []    # list of override events

def _generate_key_id() -> str:
    return f"key_{int(time.time()*1000)}"

# --- Override resolver and audit -----------------------------------------
class Override:
    def __init__(self, resolved_duration: Optional[int], role_id: Optional[str], applied_by_admin: bool):
        self.resolved_duration = resolved_duration
        self.role_id = role_id
        self.applied_by_admin = applied_by_admin

def resolve_override(app: Flask, requester_id: str, requested_role: str, payload: dict) -> Override:
    """
    Determine final override decisions in a single place.
    Precedence:
      1. If admin_override True and requester is admin -> honor requested duration
      2. Else if app.cfg.ALLOW_CUSTOM_KEY is False and mode==custom -> raise ValidationError
      3. Else use defaults (quick defaults)
    This function logs the resolution and records an audit event.
    """
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

    # Case: explicit admin override
    if payload.get("admin_override", False):
        if not is_admin:
            raise AuthorizationError("admin_override requested by non-admin")
        applied_by_admin = True
        if payload.get("duration_minutes"):
            resolved_duration = int(payload["duration_minutes"])
    # Case: custom mode but custom keys disabled globally
    if mode == "custom" and not cfg.ALLOW_CUSTOM_KEY and not applied_by_admin:
        raise ValidationError("custom keys are disabled by server configuration")
    # Default durations
    if resolved_duration is None:
        if mode == "quick":
            resolved_duration = 10  # minutes default for quick keys
        else:
            # custom mode requested and either provided duration or fallback to 60
            resolved_duration = int(payload.get("duration_minutes") or 60)

    # record audit
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
    logger.info(json.dumps({"event": "override.resolved", "requester_id": requester_id, "role": requested_role, "duration": resolved_duration, "admin": applied_by_admin}))
    return Override(resolved_duration=resolved_duration, role_id=requested_role, applied_by_admin=applied_by_admin)

# --- Key creation flows ---------------------------------------------------
def _store_key_record(record: dict) -> dict:
    with _store_lock:
        key_id = _generate_key_id()
        record["key_id"] = key_id
        record["created_at"] = datetime.utcnow().isoformat()
        _KEYS_STORE[key_id] = record
    return record

def quick_key_create(app: Flask, payload: dict) -> dict:
    """
    Create a quick key. This must not be triggered by 'custom' mode.
    """
    if payload.get("mode") != "quick":
        raise ValidationError("quick_key_create called with non-quick mode")
    # validate and resolve override
    validated = validate_key_payload(payload)
    override = resolve_override(app, validated["user_id"], validated["role_id"], validated)
    # quick generator ignores any requested custom duration unless admin_override applied
    duration = override.resolved_duration
    record = {
        "type": "quick",
        "user_id": validated["user_id"],
        "role_id": override.role_id,
        "duration_minutes": duration,
        "applied_by_admin": override.applied_by_admin
    }
    stored = _store_key_record(record)
    app.logger_custom.info(json.dumps({"event": "key.created", "key_id": stored["key_id"], "type": "quick", "user_id": stored["user_id"]}))
    return {"ok": True, "key": stored}

def custom_key_create(app: Flask, payload: dict) -> dict:
    """
    Create a custom key. Must not fallback to quick_key_create automatically.
    """
    if payload.get("mode") != "custom":
        raise ValidationError("custom_key_create called with non-custom mode")
    validated = validate_key_payload(payload)
    override = resolve_override(app, validated["user_id"], validated["role_id"], validated)
    # ensure custom flow uses requested duration (or resolved)
    duration = override.resolved_duration
    record = {
        "type": "custom",
        "user_id": validated["user_id"],
        "role_id": override.role_id,
        "duration_minutes": duration,
        "applied_by_admin": override.applied_by_admin
    }
    stored = _store_key_record(record)
    app.logger_custom.info(json.dumps({"event": "key.created", "key_id": stored["key_id"], "type": "custom", "user_id": stored["user_id"]}))
    return {"ok": True, "key": stored}

# Small helpers to inspect store (for admin or tests)
def list_keys() -> list:
    with _store_lock:
        return list(_KEYS_STORE.values())

def list_override_audit() -> list:
    with _store_lock:
        return list(_OVERRIDES_AUDIT)

# app.py  -- Part 4 of 4
from flask import request

# --- Routes ---------------------------------------------------------------
def _is_admin(app: Flask, user_id: str) -> bool:
    try:
        uid = int(str(user_id))
        return uid in app.cfg.ADMIN_USER_IDS
    except Exception:
        return False

@app.route("/create-key", methods=["POST"])
def create_key_route():
    """
    Creates a key. Expects JSON body validated by validate_key_payload.
    'mode' must be explicit or defaults to quick. This endpoint dispatches
    to the correct creation flow and guarantees custom flow never triggers quick flow.
    """
    payload = request.get_json(silent=True) or {}
    # normalize mode early
    try:
        normalized = validate_key_payload(payload)
    except ValidationError as e:
        raise

    # ensure explicit mode dispatch
    mode = normalized["mode"]
    # attach requester id if missing (try header)
    if not normalized["user_id"]:
        normalized["user_id"] = request.headers.get("X-User-Id") or "anonymous"

    # dispatch
    if mode == "quick":
        result = quick_key_create(app, normalized)
    else:
        result = custom_key_create(app, normalized)
    return jsonify(result), 200

@app.route("/postback", methods=["POST"])
def postback_route():
    """
    Tolerant postback handler: accepts many shapes and never crashes if non-critical fields are missing.
    Returns 200 and logs the processing. Downstream logic (e.g., awarding roles) should be idempotent.
    """
    payload = request.get_json(silent=True) or {}
    validated = validate_postback_payload(payload)
    app.logger_custom.info(json.dumps({"event": "postback.received", "tx": validated["transaction_id"], "status": validated["status"]}))
    # simple mock processing: if status == completed and user present, create a quick key
    try:
        if validated["status"].lower() in ("completed", "success", "ok") and validated["user_id"]:
            # create a quick key grant as a side-effect
            create_payload = {
                "mode": "quick",
                "user_id": validated["user_id"],
                "role_id": validated["metadata"].get("role_id", "default_role"),
                # do not allow external postbacks to set admin_override
                "admin_override": False
            }
            quick_key_create(app, create_payload)
    except Exception as exc:
        # tolerate processing errors but do not raise 500 to caller
        app.logger_custom.warning(json.dumps({"event": "postback.processing_error", "tx": validated["transaction_id"], "error": repr(exc)}))
    return jsonify({"ok": True, "tx": validated["transaction_id"]}), 200

@app.route("/admin/keys", methods=["GET"])
def admin_list_keys():
    """
    Admin-only inspect endpoint to list keys. Caller must provide X-User-Id header of admin.
    """
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

# register exception handlers with the app instance if not already registered
try:
    _register_exception_handlers(app)
except Exception:
    pass

# basic Liveness
@app.route("/_health", methods=["GET"])
def health():
    return jsonify({"ok": True, "status": "healthy", "req_id": getattr(g, "request_id", None)}), 200

# run for local debug
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=app.config.get("DEBUG", False))