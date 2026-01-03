from datetime import datetime
import json

from .exceptions import AuthorizationError, ValidationError
from .stores import _OVERRIDES_AUDIT, _store_lock


class Override:
    """
    Represents the resolved override result:
    - resolved_duration: final duration in minutes
    - role_id: role to assign
    - applied_by_admin: whether admin override was used
    """
    def __init__(self, resolved_duration, role_id, applied_by_admin):
        self.resolved_duration = resolved_duration
        self.role_id = role_id
        self.applied_by_admin = applied_by_admin


def resolve_override(app, requester_id: str, requested_role: str, payload: dict) -> Override:
    """
    Resolve duration and role overrides based on:
    - admin privileges
    - custom mode rules
    - server configuration
    - payload parameters
    """

    cfg = app.cfg
    logger = app.logger_custom

    mode = payload.get("mode", "quick")

    # -----------------------------
    # Admin detection
    # -----------------------------
    is_admin = False
    try:
        rid = int(str(requester_id))
        is_admin = rid in cfg.ADMIN_USER_IDS
    except Exception:
        is_admin = False

    applied_by_admin = False
    resolved_duration = None

    # -----------------------------
    # Admin override path
    # -----------------------------
    if payload.get("admin_override", False):
        if not is_admin:
            raise AuthorizationError("admin_override requested by non-admin")

        applied_by_admin = True

        if payload.get("duration_minutes"):
            resolved_duration = int(payload["duration_minutes"])

    # -----------------------------
    # Custom mode gating
    # -----------------------------
    if mode == "custom" and not cfg.ALLOW_CUSTOM_KEY and not applied_by_admin:
        raise ValidationError("custom keys are disabled by server configuration")

    # -----------------------------
    # Default duration resolution
    # -----------------------------
    if resolved_duration is None:
        if mode == "quick":
            resolved_duration = 10
        else:
            resolved_duration = int(payload.get("duration_minutes") or 60)

    # -----------------------------
    # Audit logging
    # -----------------------------
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

    return Override(
        resolved_duration=resolved_duration,
        role_id=requested_role,
        applied_by_admin=applied_by_admin
    )