from flask import Blueprint, request, jsonify
from urllib.parse import unquote_plus
from datetime import datetime
import time

from core.key_store import (
    _get_key_from_store,
    burn_key,
    LEGACY_LIMIT_SECONDS,
    get_db
)
from core.admin_override import global_override, admin_overrides

validate_bp = Blueprint("validate", __name__)

@validate_bp.route("/validate_key", methods=["GET", "POST"])
@validate_bp.route("/validate_key/<path:key_to_validate>", methods=["GET"])
@validate_bp.route("/validate_key/<did>/<path:key_to_validate>", methods=["GET"])
def validate_key(key_to_validate=None, did=None):
    try:
        # POST JSON
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            key_to_validate = data.get("key")

        # GET
        if request.method == "GET":
            key_to_validate = key_to_validate or request.args.get("key")

        if not key_to_validate:
            return jsonify({"ok": False, "valid": False, "message": "No key provided"}), 400

        key_to_validate = unquote_plus(str(key_to_validate)).strip()
        now = time.time()

        # ADMIN OVERRIDE
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
            # LOOKUP FROM MYSQL
            record = _get_key_from_store(key_to_validate)
            if not record:
                return jsonify({"ok": False, "valid": False, "message": "Invalid or unknown key"}), 400

            # -------------------------------------------------
            # REAL CLIENT IP (from PHP → Python)
            # -------------------------------------------------
            real_ip = request.headers.get("X-Real-IP")
            request_ip = real_ip or request.remote_addr or "unknown"

            print("Client IP received:", request_ip)

            key_ip = record.get("created_ip")

            # -------------------------------------------------
            # AUTO‑ASSIGN IP IF NULL
            # -------------------------------------------------
            if not key_ip or key_ip.strip() == "":
                try:
                    db = get_db()
                    cursor = db.cursor()
                    cursor.execute("""
                        UPDATE generated_keys
                        SET created_ip = %s
                        WHERE key_value = %s
                    """, (request_ip, key_to_validate))
                    db.commit()
                    cursor.close()
                    db.close()
                    print("Assigned new IP to key:", request_ip)
                except Exception as e:
                    print("Failed to assign IP:", e)

                key_ip = request_ip  # treat as assigned

            # -------------------------------------------------
            # IP MISMATCH CHECK
            # -------------------------------------------------
            if key_ip != request_ip:
                return jsonify({
                    "ok": False,
                    "valid": False,
                    "message": "Sharing keys is forbidden",
                    "request_ip": request_ip,
                    "key_ip": key_ip
                }), 403

            # EXPIRY PARSE
            try:
                rec_expires_at = float(record.get("expires_at") or 0)
            except Exception:
                return jsonify({"ok": False, "valid": False, "message": "Malformed expiry"}), 500

            # EXPIRED
            if now > rec_expires_at:
                try:
                    burn_key(key_to_validate)
                except Exception:
                    pass

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

        # FIELD FILTERING
        fields_param = request.args.get("fields")
        if fields_param:
            requested = {f.strip() for f in fields_param.split(",")}
            filtered = {k: v for k, v in response.items() if k in requested}

            filtered.setdefault("ok", response["ok"])
            filtered.setdefault("valid", response["valid"])
            filtered.setdefault("message", response["message"])

            return jsonify(filtered), 200

        return jsonify(response), 200

    except Exception as e:
        return jsonify({
            "ok": False,
            "valid": False,
            "message": f"Server error: {type(e).__name__} - {str(e)}"
        }), 500
