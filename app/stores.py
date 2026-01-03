import time
import threading
from datetime import datetime
from typing import Optional

from .exceptions import ValidationError


# -----------------------------
# Thread‑safe in‑memory stores
# -----------------------------

_store_lock = threading.RLock()

# key_id -> record
_KEYS_STORE = {}

# audit log for overrides
_OVERRIDES_AUDIT = []

# Global override flags
global_override = False
admin_overrides = {}

# Legacy expiry window
LEGACY_LIMIT_SECONDS = 3600


# -----------------------------
# Store Helpers
# -----------------------------

def burn_key(key_to_burn: str):
    """
    Mark a key as revoked in the store.
    """
    with _store_lock:
        key_info = _KEYS_STORE.get(key_to_burn)
        if key_info:
            key_info["status"] = "revoked"
            _KEYS_STORE[key_to_burn] = key_info


def list_keys() -> list:
    """
    Return all key records.
    """
    with _store_lock:
        return list(_KEYS_STORE.values())


def list_override_audit() -> list:
    """
    Return all override audit entries.
    """
    with _store_lock:
        return list(_OVERRIDES_AUDIT)


def _get_key_from_store(key_id: str) -> Optional[dict]:
    """
    Retrieve a key record by ID.
    """
    with _store_lock:
        return _KEYS_STORE.get(key_id)


# -----------------------------
# Internal key ID generator
# -----------------------------

def _generate_key_id() -> str:
    """
    Generate a unique key ID based on timestamp.
    """
    return f"key_{int(time.time() * 1000)}"


# -----------------------------
# Store write helper
# -----------------------------

def store_key_record(record: dict, key_id: Optional[str] = None) -> dict:
    """
    Persist a key record into the in‑memory store with thread‑safety.
    """
    with _store_lock:
        if key_id:
            if key_id in _KEYS_STORE:
                raise ValidationError("custom key string already exists")
            record["key_id"] = key_id
        else:
            record["key_id"] = _generate_key_id()

        record.setdefault("status", "active")
        record["created_at"] = datetime.utcnow().isoformat()

        _KEYS_STORE[record["key_id"]] = record
        return _KEYS_STORE[record["key_id"]]