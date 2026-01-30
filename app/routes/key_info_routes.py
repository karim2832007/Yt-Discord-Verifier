from flask import Blueprint, jsonify
from app.models.key import Key
from flask import session

bp = Blueprint("key_info_routes", __name__)

@bp.get("/key/info/<key_value>")
def key_info(key_value):
    key = Key.query.filter_by(key_value=key_value).first()

    if not key:
        return jsonify({"ok": False, "message": "Key not found"}), 404

    return jsonify({
        "ok": True,
        "key": key.to_record(),
        "devices": len(key.devices)
    }), 200

@bp.get("/key/user/<int:user_id>")
def get_user_keys(user_id):
    keys = Key.query.filter_by(user_id=user_id).all()
    return jsonify({
        "ok": True,
        "keys": [k.to_record() for k in keys]
    }), 200
