from flask import Blueprint, request, jsonify
from datetime import datetime
from app.models.key import Key

bp = Blueprint("verifier_routes", __name__)

@bp.get("/validate_key/<key_value>")
def validate_key(key_value):
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

    resp = {
        "ok": True,
        "valid": True,
        "message": "Key valid.",
        "expires_at": key.expires_at
    }

    fields = request.args.get("fields")
    if fields:
        wanted = {f.strip() for f in fields.split(",")}
        resp = {k: v for k, v in resp.items() if k in wanted or k == "ok"}

    return jsonify(resp), 200