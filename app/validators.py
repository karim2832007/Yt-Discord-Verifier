from datetime import datetime
from .exceptions import ValidationError


# -----------------------------
# Basic Validators
# -----------------------------

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


# -----------------------------
# Payload Validators
# -----------------------------

def validate_key_payload(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValidationError("payload must be a JSON object")

    mode = data.get("mode", "quick")
    mode = _ensure_str(mode, "mode").lower()

    if mode not in ("quick", "custom"):
        raise ValidationError("mode must be 'quick' or 'custom'")

    # user_id
    user_id_raw = data.get("user_id")
    user_id = _ensure_str(str(user_id_raw), "user_id") if user_id_raw is not None else ""

    # role_id
    role_id_raw = data.get("role_id")
    role_id = _ensure_str(str(role_id_raw), "role_id") if role_id_raw is not None else "default_role"

    admin_override = _ensure_bool_like(data.get("admin_override", False))

    duration_minutes = None

    if mode == "custom":
        duration_raw = data.get("duration_minutes")
        duration_minutes = _ensure_int(duration_raw, "duration_minutes", minimum=1, maximum=60 * 24 * 30)

    elif mode == "quick":
        dur = data.get("duration_minutes")
        if dur is not None and dur != "":
            duration_minutes = _ensure_int(dur, "duration_minutes", minimum=1, maximum=60 * 24 * 30)

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