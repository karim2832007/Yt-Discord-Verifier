from flask import Blueprint, request, jsonify
from urllib.parse import unquote_plus
from datetime import datetime
import time

from ..stores import (
    _get_key_from_store,
    burn_key,
    global_override,
    admin_overrides,
    LEGACY_LIMIT_SECONDS
)

bp = Blueprint("validate", __name__)


@bp.route("/validate_key", methods=["GET", "POST"])
@bp.route("/validate_key/<path:key_to_validate>", methods=["GET"])
@bp.route("/validate_key/<did>/<path:key_to_validate>", methods=["GET"])
def validate_key(key_to_validate=None, did=None):
    """
    Validate a key and return full expiry information.
    Always returns ok, valid, message, and expiry fields.
    """
    from flask import current_app as app

    try:
        # -----------------------------
        # POST JSON body
        # -----------------------------
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            key_to_validate = data.get("key")

        # -----------------------------
        # GET with ?key=... or path segment
        # -----------------------------
        if request.method == "GET":
            key_to_validate = key_to_validate or request.args.get("key")

        if not key_to_validate:
            return jsonify({"ok": False, "valid": False, "message": "No key provided"}), 400

        key_to_validate = unquote_plus(str(key_to_validate)).strip()
        now = time.time()

        # -----------------------------
        # Admin override path
        # -----------------------------
        if global_override or (did and admin_overrides.get(did)):
            expires_at = float(now + LEGACY_LIMIT_SECONDS)
            response = {
                "ok": True,
                "valid": True,
                "message": "ADMIN OVERRIDE ACTIVE",
                "expires_at": expires_at,
                "expiry_iso": datetime.utcfromtimestamp(expires_at).isoformat(),
                "expires_in": int(expires_at - now)
            }

        else:
            # -----------------------------
            # Lookup record
            # -----------------------------
            record = _get_key_from_store(key_to_validate)
            if not record:
                return jsonify({"ok": False, "valid": False, "message": "Invalid or unknown key"}), 400

            try:
                rec_expires_at = float(record.get("expires_at") or 0)
            except Exception:
                return jsonify({"ok": False, "valid": False, "message": "Malformed expiry"}), 500

            # -----------------------------
            # Expired key
            # -----------------------------
            if now > rec_expires_at:
                try:
                    burn_key(key_to_validate)
                except Exception:
                    app.logger_custom.exception("burn_key failed")

                return jsonify({"ok": False, "valid": False, "message": "Key expired"}), 410

            status = record.get("status", "active")
            valid = (status == "active")

            response = {
                "ok": True,
                "valid": valid,
                "message": "Key is valid" if valid else "Key is revoked",
                "expires_at": rec_expires_at,
                "expiry_iso": datetime.utcfromtimestamp(rec_expires_at).isoformat(),
                "expires_in": int(rec_expires_at - now)
            }

        # -----------------------------
        # Optional field filtering
        # -----------------------------
        fields_param = request.args.get("fields")
        if fields_param:
            requested = {f.strip() for f in fields_param.split(",")}
            filtered = {k: v for k, v in response.items() if k in requested}

            # Always include ok/valid/message
            filtered.setdefault("ok", response["ok"])
            filtered.setdefault("valid", response["valid"])
            filtered.setdefault("message", response["message"])

            return jsonify(filtered), 200

        # -----------------------------
        # Default: full response
        # -----------------------------
        return jsonify(response), 200

    except Exception as e:
        app.logger_custom.exception(f"Validation failed: {e}")
        return jsonify({
            "ok": False,
            "valid": False,
            "message": f"Server error: {type(e).__name__} - {str(e)}"
        }), 500