from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models.key import Key
from flask import session

bp = Blueprint("key_admin_routes", __name__)

@bp.post("/key/revoke")
def revoke_key():
    data = request.get_json(silent=True) or {}
    key_value = data.get("key")

    if not key_value:
        return jsonify({"ok": False, "message": "Missing key"}), 400

    key = Key.query.filter_by(key_value=key_value).first()

    if not key:
        return jsonify({"ok": False, "message": "Key not found"}), 404

    key.status = "revoked"
    db.session.commit()

    return jsonify({"ok": True, "message": "Key revoked"}), 200

@bp.get("/key/list")
def list_keys():
    keys = Key.query.all()
    return jsonify({
        "ok": True,
        "keys": [k.to_record() for k in keys]
    }), 200

