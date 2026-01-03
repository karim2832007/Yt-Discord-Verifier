from flask import Blueprint, request, jsonify
from datetime import datetime
import time

from ..validators import validate_postback_payload
from ..key_manager import quick_key_create
from ..stores import _store_lock, _KEYS_STORE

bp = Blueprint("postback", __name__)


@bp.route("/postback", methods=["GET", "POST"])
def postback_route():
    """
    Webhook: on completed transaction, auto-create a quick key for the user.
    Supports both GET (tracking networks) and POST (JSON webhooks).
    """
    from flask import current_app as app

    # -----------------------------
    # 1. Normalize payload (GET or POST)
    # -----------------------------
    if request.method == "GET":
        # GET payload comes from query params
        payload = {
            "transaction_id": request.args.get("tx") or request.args.get("transaction_id"),
            "status": request.args.get("status", "unknown"),
            "user_id": request.args.get("uid") or request.args.get("user_id"),
            "metadata": {
                "role_id": request.args.get("role_id", "default_role")
            }
        }
    else:
        # POST payload comes from JSON
        payload = request.get_json(silent=True) or {}

    # Validate + normalize
    validated = validate_postback_payload(payload)

    app.logger_custom.info({
        "event": "postback.received",
        "tx": validated["transaction_id"],
        "status": validated["status"],
        "method": request.method
    })

    # -----------------------------
    # 2. Process successful transactions
    # -----------------------------
    try:
        if validated["status"].lower() in ("completed", "success", "ok") and validated["user_id"]:
            create_payload = {
                "mode": "quick",
                "user_id": validated["user_id"],
                "role_id": validated["metadata"].get("role_id", "default_role"),
                "admin_override": False
            }

            created = quick_key_create(app, create_payload)

            # Normalize expiry fields
            record = created.get("key", {})
            if not record.get("expires_at"):
                record["expires_at"] = time.time() + 24 * 3600

            record["expires_at"] = float(record["expires_at"])
            record["expiry_iso"] = datetime.utcfromtimestamp(record["expires_at"]).isoformat()

            # Store key
            with _store_lock:
                _KEYS_STORE[record["key_id"]] = record

    except Exception as exc:
        app.logger_custom.warning({
            "event": "postback.processing_error",
            "tx": validated["transaction_id"],
            "error": repr(exc)
        })

    # -----------------------------
    # 3. Always return OK (webhooks expect 200)
    # -----------------------------
    return jsonify({"ok": True, "tx": validated["transaction_id"]}), 200
