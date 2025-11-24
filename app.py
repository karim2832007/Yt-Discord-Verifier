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
import pytz
import importlib
import string, secrets
import requests
from urllib.parse import unquote_plus
from flask import Flask, request, g, jsonify, session, redirect, url_for, make_response
from flask_cors import CORS
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

        # ✅ Session cookie settings (indented inside __init__)
        self.SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "gamingmods_session")
        self.SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
        self.SESSION_COOKIE_SECURE = str(os.getenv("SESSION_COOKIE_SECURE", "1")).lower() in ("1", "true", "yes")
        self.SESSION_COOKIE_DOMAIN = os.getenv("SESSION_COOKIE_DOMAIN", ".gaming-mods.com")
        self.SESSION_COOKIE_HTTPONLY = True

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
        SESSION_COOKIE_SECURE=cfg.SESSION_COOKIE_SECURE,
        SESSION_COOKIE_DOMAIN=cfg.SESSION_COOKIE_DOMAIN
    )

    # Attach config and logger
    app.cfg = cfg
    logger = make_logger(logfile=cfg.LOG_FILE)
    app.logger_custom = logger

    # ✅ Apply CORS inside the function
    CORS(app, supports_credentials=True, origins=["https://gaming-mods.com"])

    # ✅ Handle OPTIONS requests
    @app.before_request
    def handle_options():
        if request.method == 'OPTIONS':
            return make_response('', 200)

    # ✅ Add request-id filter for logging
    class ReqIdFilter(logging.Filter):
        def filter(self, rec):
            rec.req_id = getattr(g, "request_id", "-")
            return True

    logger.addFilter(ReqIdFilter())

    return app

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

def burn_key(key_to_burn: str):
    """Internal helper: mark a key as revoked in the store."""
    with _store_lock:
        key_info = _KEYS_STORE.get(key_to_burn)
        if key_info:
            key_info["status"] = "revoked"
            _KEYS_STORE[key_to_burn] = key_info
            app.logger_custom.info(json.dumps({
                "event": "key.burned",
                "key_id": key_to_burn,
                "user_id": key_info.get("user_id")
            }))

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
_KEYS_STORE = {}          # key_id -> record
_OVERRIDES_AUDIT = []     # audit entries
global_override = False
admin_overrides = {}
LEGACY_LIMIT_SECONDS = 3600
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

    # admin detection
    is_admin = False
    try:
        rid = int(str(requester_id))
        is_admin = rid in cfg.ADMIN_USER_IDS
    except Exception:
        is_admin = False

    applied_by_admin = False
    resolved_duration = None

    # admin override path
    if payload.get("admin_override", False):
        if not is_admin:
            raise AuthorizationError("admin_override requested by non-admin")
        applied_by_admin = True
        if payload.get("duration_minutes"):
            resolved_duration = int(payload["duration_minutes"])

    # custom mode gating
    if mode == "custom" and not cfg.ALLOW_CUSTOM_KEY and not applied_by_admin:
        raise ValidationError("custom keys are disabled by server configuration")

    # default duration resolution
    if resolved_duration is None:
        if mode == "quick":
            resolved_duration = 10
        else:
            resolved_duration = int(payload.get("duration_minutes") or 60)

    # audit
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
    """Persist a key record into the in-memory store with thread-safety."""
    with _store_lock:
        if key_id:
            if key_id in _KEYS_STORE:
                raise ValidationError("custom key string already exists")
            record["key_id"] = key_id
        else:
            record["key_id"] = _generate_key_id()

        # optional expiry passthrough: if caller provided ISO expiry, retain it
        record.setdefault("status", "active")
        record["created_at"] = datetime.utcnow().isoformat()
        _KEYS_STORE[record["key_id"]] = record
        return _KEYS_STORE[record["key_id"]]



def generate_random_key(length=10) -> str:
    """Generate a random alphanumeric key string of given length."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def quick_key_create(app: Flask, payload: dict) -> dict:
    """Internal helper: create a quick key (not a public route)."""
    if payload.get("mode") != "quick":
        raise ValidationError("quick_key_create called with non-quick mode")

    validated = validate_key_payload(payload)
    override = resolve_override(app, validated["user_id"] or "anonymous",
                                validated["role_id"], validated)
    duration = override.resolved_duration

    # Build the record
    record = {
        "type": "quick",
        "user_id": validated["user_id"],
        "role_id": override.role_id,
        "duration_minutes": duration,
        "applied_by_admin": override.applied_by_admin,
    }

    # Add expiry: use provided one or default to 24h
    if "expiry" in validated:
        record["expiry"] = validated["expiry"]
    else:
        record["expiry"] = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    # Generate a random 10-character key string
    key_id = generate_random_key(10)
    record["key_id"] = key_id
    record["created_at"] = datetime.utcnow().isoformat()
    record["status"] = "active"

    # Store in memory
    with _store_lock:
        _KEYS_STORE[key_id] = record

    app.logger_custom.info(json.dumps({
        "event": "key.created",
        "key_id": key_id,
        "type": "quick",
        "user_id": record["user_id"]
    }))

    return {"ok": True, "key": record}
    
def custom_key_create(app: Flask, payload: dict) -> dict:
    """Internal helper: create a custom key (not a public route)."""
    if payload.get("mode") != "custom":
        raise ValidationError("custom_key_create called with non-custom mode")

    validated = validate_key_payload(payload)
    override = resolve_override(app, validated["user_id"] or "anonymous", validated["role_id"], validated)
    duration = override.resolved_duration
    custom_key = payload.get("custom_key_string")

    base_record = {
        "type": "custom",
        "user_id": validated["user_id"],
        "role_id": override.role_id,
        "duration_minutes": duration,
        "applied_by_admin": override.applied_by_admin,
    }
    if "expiry" in validated:
        base_record["expiry"] = validated["expiry"]

    if custom_key is not None:
        if not override.applied_by_admin:
            raise AuthorizationError("only admin may set custom key string")
        if not re.match(r"^[A-Za-z0-9\-_]{4,64}$", custom_key):
            raise ValidationError("custom_key_string invalid format; allowed A-Z a-z 0-9 - _ length 4-64")
        stored = _store_key_record(base_record, key_id=custom_key)
    else:
        stored = _store_key_record(base_record)

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

def _get_key_from_store(key_id: str) -> Optional[dict]:
    with _store_lock:
        return _KEYS_STORE.get(key_id)

from datetime import datetime, timedelta
import pytz

@app.route("/validate_key", methods=["GET", "POST"])
@app.route("/validate_key/<path:key_to_validate>", methods=["GET"])
@app.route("/validate_key/<did>/<path:key_to_validate>", methods=["GET"])
def validate_key(key_to_validate=None, did=None):
    """
    Validate a key and return requested fields.
    Legacy mode: always returns ok, valid, message for Ren'Py client.
    """

    try:
        # Handle POST JSON body
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            key_to_validate = data.get("key")

        # Handle GET with ?key=... or path segment
        if request.method == "GET":
            key_to_validate = key_to_validate or request.args.get("key")

        if not key_to_validate:
            return jsonify({"ok": False, "valid": False, "message": "No key provided"}), 400

        try:
            key_to_validate = unquote_plus(str(key_to_validate)).strip()
        except Exception:
            key_to_validate = str(key_to_validate).strip()

        now = time.time()

        # Admin override
        if global_override or (did and admin_overrides.get(did)):
            expires_at = now + LEGACY_LIMIT_SECONDS
            response = {
                "ok": True,
                "valid": True,
                "message": "ADMIN OVERRIDE ACTIVE",
                "expires_at": float(expires_at),
                "expires_in": int(expires_at - now)
            }
        else:
            # Lookup record
            record = _get_key_from_store(key_to_validate)
            if not record:
                return jsonify({"ok": False, "valid": False, "message": "Invalid or unknown key"}), 400

            try:
                raw_exp = float(record.get("expires_at") or 0)
                # interpret expiry as UTC
                utc_exp = datetime.fromtimestamp(raw_exp, tz=pytz.UTC)

                # detect server's local timezone dynamically
                local_tz = datetime.now().astimezone().tzinfo

                # convert expiry to local time and subtract one hour
                adjusted_exp = utc_exp.astimezone(local_tz) - timedelta(hours=1)
                rec_expires_at = adjusted_exp.timestamp()
            except Exception:
                return jsonify({"ok": False, "valid": False, "message": "Malformed expiry"}), 500

            if now > rec_expires_at:
                try:
                    burn_key(key_to_validate)
                except Exception:
                    app.logger.exception("burn_key failed")
                return jsonify({"ok": False, "valid": False, "message": "Key expired"}), 410

            status = record.get("status", "active")
            valid = (status == "active")

            response = {
                "ok": True,
                "valid": valid,
                "message": "Key is valid" if valid else "Key is revoked",
                "expires_at": rec_expires_at,
                "expires_in": int(rec_expires_at - now)
            }

        # Legacy mode: always return ok, valid, message for Ren'Py
        if request.args.get("legacy") == "1" or request.headers.get("User-Agent") == "RenPy-Client":
            return jsonify({
                "ok": response.get("ok"),
                "valid": response.get("valid"),
                "message": response.get("message")
            }), 200

        # Filter response if fields=... is provided
        fields_param = request.args.get("fields")
        if fields_param:
            requested = {f.strip() for f in fields_param.split(",")}
            filtered = {k: v for k, v in response.items() if k in requested}
            filtered.setdefault("ok", response.get("ok"))
            filtered.setdefault("valid", response.get("valid"))
            return jsonify(filtered), 200

        # Default: full response
        return jsonify(response), 200

    except Exception as e:
        app.logger.exception("Validation failed: %s", e)
        return jsonify({
            "ok": False,
            "valid": False,
            "message": f"Server error: {type(e).__name__} - {str(e)}"
        }), 500
        
@app.route("/keys/burn", methods=["POST"])
def keys_burn():
    """Public: burn (revoke) a key by ID."""
    data = request.get_json(silent=True) or {}
    key_to_burn = data.get("key")
    if not key_to_burn:
        return jsonify({"ok": False, "message": "No key provided"}), 400

    with _store_lock:
        key_info = _KEYS_STORE.get(key_to_burn)
        if not key_info:
            return jsonify({"ok": False, "message": "Key not found"}), 404

        # Mark as revoked
        key_info["status"] = "revoked"
        _KEYS_STORE[key_to_burn] = key_info

    app.logger_custom.info(json.dumps({
        "event": "key.burned",
        "key_id": key_to_burn,
        "user_id": key_info.get("user_id")
    }))

    return jsonify({"ok": True, "message": f"Key {key_to_burn} burned"}), 200

@app.route("/create-key", methods=["POST"])
def create_key_route():
    """Public: create a key. Returns JSON for API clients, redirect for browser flows."""
    payload = request.get_json(silent=True) or {}
    try:
        normalized = validate_key_payload(payload)
    except ValidationError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    # Prefer the logged-in session user ID
    if not normalized.get("user_id"):
        if "user" in session and session["user"].get("id"):
            normalized["user_id"] = str(session["user"]["id"])
        else:
            normalized["user_id"] = request.headers.get("X-User-Id") or "anonymous"

    mode = normalized.get("mode", "quick")
    if mode == "quick":
        new_key = quick_key_create(app, normalized)
    else:
        new_key = custom_key_create(app, normalized)

    # Ensure expiry is set (default 24h from now)
    if isinstance(new_key, dict) and not new_key.get("expiry"):
        new_key["expiry"] = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    # Decide whether to return JSON or redirect
    wants_json = (
        request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in (request.headers.get("Accept") or "")
    )

    if wants_json:
        return jsonify({
            "ok": True,
            "key": new_key,
            "user_id": normalized["user_id"]
        }), 200

    return redirect("/keys")


@app.route("/generate_key", methods=["POST"])
def generate_key_alias():
    return create_key_route()

@app.route("/postback", methods=["POST"])
def postback_route():
    """Webhook: on completed transaction, auto-create a quick key for the user."""
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

@app.route("/admin")
def admin():
    return render_template("admin.html")


@app.route("/keys", methods=["GET"])
def keys():
    """Return all keys for the logged-in user as JSON."""
    try:
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not authenticated"}), 401

        user_id = str(user.get("id"))
        with _store_lock:
            user_keys = [
                k for k in _KEYS_STORE.values()
                if str(k.get("user_id")) == user_id
            ]

        formatted = []
        for k in user_keys:
            status = k.get("status", "active")
            expiry_date = k.get("expiry")
            expired = False

            if expiry_date:
                try:
                    dt_expiry = datetime.fromisoformat(expiry_date)
                    expired = datetime.utcnow() > dt_expiry
                except Exception as e:
                    app.logger.warning(f"Expiry parse failed: {expiry_date} ({e})")
                    expired = False

            valid = (status == "active" and not expired)

            formatted.append({
                "key_id": k.get("key_id"),
                "type": k.get("type"),
                "owner": k.get("user_id"),
                "role_id": k.get("role_id"),
                "created_at": k.get("created_at"),
                "expiry": expiry_date,
                "status": status,
                "valid": valid,
                "message": "Key is valid" if valid else "Key is revoked or expired",
                "actions": {
                    "copy_hint": f"POST /validate_key {{'key':'{k.get('key_id')}'}}",
                    "burn_hint": f"POST /keys/burn {{'key':'{k.get('key_id')}'}}"
                }
            })

        return jsonify({
            "ok": True,
            "user_id": user_id,
            "keys": formatted
        }), 200

    except Exception as e:
        app.logger.exception(f"Failed to list keys: {e}")
        return jsonify({"ok": False, "message": "Server error"}), 500

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
from functools import wraps
from flask import request, jsonify, session, current_app, abort

# Minimal admin check decorator (replace with your auth logic if different)
def require_admin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        user = session.get("user")
        owner_id = current_app.config.get("OWNER_ID")
        # allow local override for testing: OWNER_ID can be str or int
        if owner_id is not None and user and str(user.get("id")) == str(owner_id):
            return f(*args, **kwargs)
        return jsonify({"error": "unauthorized"}), 403
    return wrapped

# In-memory placeholders (swap for DB / persistent store)
_ADMIN_LOGS = ["System started", "Waiting for actions..."]
_USERS = [{"id": "123", "name": "TestUser"}]
_KEYS = [
    {"key": "ABC123", "type": "global", "expiry": "2025-12-01", "owner": "User#1234", "status": "active"}
]
_KEY_LOGS = ["Created key ABC123 for User#1234", "Revoked key XYZ789"]
_PERKS = []

# GET /admin/logs
@app.route("/admin/logs", methods=["GET"])
@require_admin
def admin_logs_view():
    return jsonify({"logs": _ADMIN_LOGS})

# POST /admin/add-perk
@app.route("/admin/add-perk", methods=["POST"])
@require_admin
def admin_add_perk():
    data = request.get_json(silent=True) or {}
    perk = data.get("perk")
    if not perk:
        return jsonify({"error": "missing perk"}), 400
    _PERKS.append(perk)
    _ADMIN_LOGS.append(f"Added perk {perk}")
    return jsonify({"status": "success", "action": f"Added perk {perk}"})

# POST /admin/remove-perk
@app.route("/admin/remove-perk", methods=["POST"])
@require_admin
def admin_remove_perk():
    data = request.get_json(silent=True) or {}
    perk = data.get("perk")
    if not perk:
        return jsonify({"error": "missing perk"}), 400
    try:
        _PERKS.remove(perk)
    except ValueError:
        return jsonify({"error": "perk not found"}), 404
    _ADMIN_LOGS.append(f"Removed perk {perk}")
    return jsonify({"status": "success", "action": f"Removed perk {perk}"})

# POST /admin/ban-user
@app.route("/admin/ban-user", methods=["POST"])
@require_admin
def admin_ban_user():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "missing user_id"}), 400
    _ADMIN_LOGS.append(f"Banned user {user_id}")
    # TODO: persist ban in DB
    return jsonify({"status": "success", "action": f"Banned user {user_id}"})

# POST /admin/unban-user
@app.route("/admin/unban-user", methods=["POST"])
@require_admin
def admin_unban_user():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "missing user_id"}), 400
    _ADMIN_LOGS.append(f"Unbanned user {user_id}")
    # TODO: remove ban in DB
    return jsonify({"status": "success", "action": f"Unbanned user {user_id}"})

# GET /admin/users
@app.route("/admin/users", methods=["GET"])
@require_admin
def admin_list_users():
    return jsonify({"users": _USERS})

# GET /admin/stats
@app.route("/admin/stats", methods=["GET"])
@require_admin
def admin_stats():
    return jsonify({
        "active_users": len(_USERS),
        "perks_count": len(_PERKS)
    })

# POST /admin/create-key
@app.route("/admin/create-key", methods=["POST"])
@require_admin
def admin_create_key():
    data = request.get_json(silent=True) or {}
    ktype = data.get("type", "one-time")
    custom = data.get("custom_key")
    expiry = data.get("expiry")
    owner = data.get("owner", "unknown")
    new_key = {
        "key": custom or f"KEY{len(_KEYS)+1:04d}",
        "type": ktype,
        "expiry": expiry or "",
        "owner": owner,
        "status": "active"
    }
    _KEYS.append(new_key)
    _KEY_LOGS.append(f"Created key {new_key['key']} for {owner}")
    return jsonify({"status": "success", "key": new_key})

# POST /admin/revoke-key
@app.route("/admin/revoke-key", methods=["POST"])
@require_admin
def admin_revoke_key():
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    if not key:
        return jsonify({"error": "missing key"}), 400
    found = next((k for k in _KEYS if k["key"] == key), None)
    if not found:
        return jsonify({"error": "not found"}), 404
    found["status"] = "revoked"
    _KEY_LOGS.append(f"Revoked key {key}")
    return jsonify({"status": "revoked", "key": key})

# GET /admin/key-logs
@app.route("/admin/key-logs", methods=["GET"])
@require_admin
def admin_key_logs():
    return jsonify({"logs": _KEY_LOGS})

@app.route("/portal/me", methods=["GET"])
def portal_me():
    user = session.get('user')
    if not user:
        return jsonify({'ok': False, 'message': 'not authenticated'}), 401
    return jsonify({'ok': True, 'user': {'id': str(user.get('id')), 'username': user.get('username')}})

@app.route("/delete-key/<key_id>", methods=["DELETE"])
def delete_key(key_id):
    """Delete (burn) a key permanently by ID."""
    with _store_lock:
        key_info = _KEYS_STORE.get(key_id)
        if not key_info:
            return jsonify({"ok": False, "message": "Key not found"}), 404

        # Mark as revoked and remove from store
        key_info["status"] = "revoked"
        _KEYS_STORE.pop(key_id, None)

    app.logger_custom.info(json.dumps({
        "event": "key.deleted",
        "key_id": key_id,
        "user_id": key_info.get("user_id")
    }))

    return jsonify({"ok": True, "message": f"Key {key_id} deleted"}), 200

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

# run for local debug
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=app.config.get("DEBUG", False))
