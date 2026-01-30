from flask import Blueprint, request, jsonify
from datetime import datetime
from app.extensions import db
from app.models.key import Key
from app.models.device import Device

bp = Blueprint("redeem_routes", __name__)

@bp.post("/redeem")
def redeem_key():
    data = request.get_json(silent=True) or {}

    key_value = data.get("key")
    device_id = data.get("device_id")

    if not key_value or not device_id:
        return jsonify({
            "ok": False,
            "valid": False,
            "message": "Missing key or device_id.",
            "expires_at": None
        }), 400

    key = Key.query.filter_by(key_value=key_value).first()

    if not key:
        return jsonify({
            "ok": False,
            "valid": False,
            "message": "Key not found.",
            "expires_at": None
        }), 404

    now_ts = datetime.utcnow().timestamp()

    if key.expires_at and now_ts > float(key.expires_at):
        return jsonify({
            "ok": False,
            "valid": False,
            "message": "Key expired.",
            "expires_at": key.expires_at
        }), 410

    if key.status != "active":
        return jsonify({
            "ok": False,
            "valid": False,
            "message": "Key revoked.",
            "expires_at": key.expires_at
        }), 400

    existing_devices = Device.query.filter_by(key_id=key.id).all()

    for d in existing_devices:
        if d.device_id == device_id:
            d.update_seen()
            db.session.commit()
            return jsonify({
                "ok": True,
                "valid": True,
                "message": "Device already activated.",
                "expires_at": key.expires_at
            }), 200

    if len(existing_devices) >= key.max_devices:
        return jsonify({
            "ok": False,
            "valid": False,
            "message": "Device limit reached.",
            "expires_at": key.expires_at
        }), 400

    new_device = Device(device_id=device_id, key_id=key.id)
    db.session.add(new_device)
    db.session.commit()

    return jsonify({
        "ok": True,
        "valid": True,
        "message": "Activated",
        "expires_at": key.expires_at
    }), 200