from flask import Blueprint, request, jsonify, session, redirect
from datetime import datetime
import time

from ..validators import validate_key_payload
from ..key_manager import quick_key_create, custom_key_create
from ..stores import _store_lock, _KEYS_STORE, burn_key

bp = Blueprint("keys", __name__)


# -----------------------------
# Burn a key
# -----------------------------
@bp.route("/keys/burn", methods=["POST"])
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

    return jsonify({"ok": True, "message": f"Key {key_to_burn} burned"}), 200


# -----------------------------
# Create a key (POST or GET)
# -----------------------------
@bp.route("/create-key", methods=["GET", "POST"])
def create_key_route():
    from flask import current_app as app

    # -----------------------------
    # POST: JSON API
    # -----------------------------
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}

        try:
            normalized = validate_key_payload(payload)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        # Prefer logged-in session user
        if not normalized.get("user_id"):
            if "user" in session and session["user"].get("id"):
                normalized["user_id"] = str(session["user"]["id"])
            else:
                normalized["user_id"] = request.headers.get("X-User-Id") or "anonymous"

        # Create the key
        mode = normalized.get("mode", "quick")
        if mode == "quick":
            created = quick_key_create(app, normalized)
        else:
            created = custom_key_create(app, normalized)

        record = created.get("key", {})

        # Ensure expiry fields exist
        if not record.get("expires_at"):
            record["expires_at"] = time.time() + 24 * 3600

        record["expires_at"] = float(record["expires_at"])
        record["expiry_iso"] = datetime.utcfromtimestamp(record["expires_at"]).isoformat()

        with _store_lock:
            _KEYS_STORE[record["key_id"]] = record

        # JSON response
        wants_json = (
            request.is_json
            or request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in (request.headers.get("Accept") or "")
        )

        if wants_json:
            return jsonify({
                "ok": True,
                "key": record,
                "user_id": normalized["user_id"]
            }), 200

        # Non‑JSON POST → redirect to keys page
        return redirect("/keys")

    # -----------------------------
    # GET: auto-generate quick key
    # -----------------------------
    if "user" in session and session["user"].get("id"):
        user_id = str(session["user"]["id"])
    else:
        user_id = request.args.get("user_id") or "anonymous"

    payload = {"mode": "quick", "user_id": user_id}
    created = quick_key_create(app, payload)
    record = created.get("key", {})

    if not record.get("expires_at"):
        record["expires_at"] = time.time() + 24 * 3600

    record["expires_at"] = float(record["expires_at"])
    record["expiry_iso"] = datetime.utcfromtimestamp(record["expires_at"]).isoformat()

    with _store_lock:
        _KEYS_STORE[record["key_id"]] = record

    # Redirect to public keys page
    return redirect("https://gaming-mods.com/keys.html")


# -----------------------------
# Alias for create-key
# -----------------------------
@bp.route("/generate_key", methods=["POST"])
def generate_key_alias():
    return create_key_route()


# -----------------------------
# List keys for logged-in user
# -----------------------------
@bp.route("/keys", methods=["GET"])
def keys():
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
        now = time.time()

        for k in user_keys:
            status = k.get("status", "active")
            expires_at = k.get("expires_at")
            expiry_iso = k.get("expiry_iso")

            expired = False
            if expires_at is not None:
                try:
                    expired = now > float(expires_at)
                except Exception:
                    expired = False

            formatted.append({
                "key_id": k.get("key_id"),
                "type": k.get("type"),
                "role_id": k.get("role_id"),
                "status": status,
                "expired": expired,
                "expires_at": expires_at,
                "expiry_iso": expiry_iso,
                "duration_minutes": k.get("duration_minutes"),
                "created_at": k.get("created_at")
            })

        return jsonify({"ok": True, "keys": formatted}), 200

    except Exception as e:
        return jsonify({"ok": False, "message": f"Server error: {e}"}), 500