import time
import re
import string
import secrets
from datetime import datetime

from .validators import validate_key_payload
from .exceptions import ValidationError, AuthorizationError
from .overrides import resolve_override
from .stores import store_key_record, _store_lock, _KEYS_STORE


# -----------------------------
# Random Key Generator
# -----------------------------

def generate_random_key(length=10) -> str:
    """
    Generate a random alphanumeric key string of given length.
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# -----------------------------
# Quick Key Creation
# -----------------------------

def quick_key_create(app, payload: dict) -> dict:
    """
    Create a quick key with default or override duration.
    """
    if payload.get("mode") != "quick":
        raise ValidationError("quick_key_create called with non-quick mode")

    validated = validate_key_payload(payload)

    override = resolve_override(
        app,
        validated["user_id"] or "anonymous",
        validated["role_id"],
        validated
    )

    duration = override.resolved_duration

    record = {
        "type": "quick",
        "user_id": validated["user_id"],
        "role_id": override.role_id,
        "duration_minutes": duration,
        "applied_by_admin": override.applied_by_admin,
        "created_at": datetime.utcnow().isoformat(),
        "status": "active",
    }

    # Always set expiry fields (default 24h)
    record["expires_at"] = float(time.time() + 24 * 3600)
    record["expiry_iso"] = datetime.utcfromtimestamp(record["expires_at"]).isoformat()

    # Generate random key ID
    key_id = generate_random_key(10)
    record["key_id"] = key_id

    with _store_lock:
        _KEYS_STORE[key_id] = record

    app.logger_custom.info({
        "event": "key.created",
        "key_id": key_id,
        "type": "quick",
        "user_id": record["user_id"]
    })

    return {"ok": True, "key": record}


# -----------------------------
# Custom Key Creation
# -----------------------------

def custom_key_create(app, payload: dict) -> dict:
    """
    Create a custom key, optionally with a custom key string (admin only).
    """
    if payload.get("mode") != "custom":
        raise ValidationError("custom_key_create called with non-custom mode")

    validated = validate_key_payload(payload)

    override = resolve_override(
        app,
        validated["user_id"] or "anonymous",
        validated["role_id"],
        validated
    )

    duration = override.resolved_duration
    custom_key = payload.get("custom_key_string")

    base_record = {
        "type": "custom",
        "user_id": validated["user_id"],
        "role_id": override.role_id,
        "duration_minutes": duration,
        "applied_by_admin": override.applied_by_admin,
        "created_at": datetime.utcnow().isoformat(),
        "status": "active",
    }

    # Always set expiry fields (default 24h)
    base_record["expires_at"] = float(time.time() + 24 * 3600)
    base_record["expiry_iso"] = datetime.utcfromtimestamp(base_record["expires_at"]).isoformat()

    # Admin custom key string
    if custom_key is not None:
        if not override.applied_by_admin:
            raise AuthorizationError("only admin may set custom key string")

        if not re.match(r"^[A-Za-z0-9\-_]{4,64}$", custom_key):
            raise ValidationError(
                "custom_key_string invalid format; allowed A-Z a-z 0-9 - _ length 4-64"
            )

        stored = store_key_record(base_record, key_id=custom_key)

    else:
        stored = store_key_record(base_record)

    app.logger_custom.info({
        "event": "key.created",
        "key_id": stored["key_id"],
        "type": "custom",
        "user_id": stored["user_id"]
    })

    return {"ok": True, "key": stored}