from flask import Blueprint, request, jsonify, redirect, session
from datetime import datetime, timedelta
from app.extensions import db
from app.models.key import Key
import uuid
import time

bp = Blueprint("key_routes", __name__)

# ---------------------------------------------------------
# Helper: create a key record
# ---------------------------------------------------------
def create_key_record(
    user_id,
    key_type="game",
    duration=1440,
    role_id=None,
    nsfw=False,
    perks=None,
    max_devices=1
):
    key_value = f"GM-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
    expires_at = (datetime.utcnow() + timedelta(minutes=duration)).timestamp()

    key = Key(
        key_value=key_value,
        user_id=user_id,
        type=key_type,
        role_id=role_id,
        duration_minutes=duration,
        expires_at=expires_at,
        nsfw=nsfw,
        perks=perks,
        max_devices=max_devices,
        created_at=time.time()
    )

    db.session.add(key)
    db.session.commit()

    return key


# ---------------------------------------------------------
# CREATE KEY (GET + POST)
# ---------------------------------------------------------
@bp.route("/create-key", methods=["GET", "POST"])
def create_key_route():

    # -----------------------------------------------------
    # POST: JSON API (React)
    # -----------------------------------------------------
    if request.method == "POST":
        data = request.get_json(silent=True) or {}

        user_id = data.get("user_id")
        if not user_id:
            return jsonify({"ok": False, "message": "Missing user_id"}), 400

        key = create_key_record(
            user_id=user_id,
            key_type=data.get("type", "game"),
            duration=int(data.get("duration_minutes", 1440)),
            role_id=data.get("role_id"),
            nsfw=bool(data.get("nsfw", False)),
            perks=data.get("perks"),
            max_devices=int(data.get("max_devices", 1))
        )

        return jsonify({"ok": True, "key": key.to_record()}), 200


    # -----------------------------------------------------
    # GET: Auto-generate quick key + redirect WITH KEY
    # -----------------------------------------------------
    if "user" in session and session["user"].get("id"):
        user_id = session["user"]["id"]
    else:
        user_id = request.args.get("user_id") or "anonymous"

    key = create_key_record(user_id=user_id)

    # Redirect WITH the key in the URL
    return redirect(f"https://gaming-mods.com/#/game-key?key={key.key_value}")


# ---------------------------------------------------------
# DELETE KEY
# ---------------------------------------------------------
@bp.delete("/<string:key_value>")
def delete_key(key_value):
    key = Key.query.filter_by(key_value=key_value).first()

    if not key:
        return jsonify({"ok": False, "message": "Key not found"}), 404

    try:
        db.session.delete(key)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "message": str(e)}), 500

    return jsonify({"ok": True, "message": "Key deleted"}), 200


# ---------------------------------------------------------
# LIST KEYS FOR USER
# ---------------------------------------------------------
@bp.get("/user/<int:user_id>")
def get_user_keys(user_id):
    keys = Key.query.filter_by(user_id=user_id).all()

    return jsonify({
        "ok": True,
        "keys": [k.to_record() for k in keys]
    }), 200


# ---------------------------------------------------------
# GET INFO FOR A SINGLE KEY
# ---------------------------------------------------------
@bp.get("/info/<string:key_value>")
def get_key_info(key_value):
    key = Key.query.filter_by(key_value=key_value).first()

    if not key:
        return jsonify({"ok": False, "message": "Key not found"}), 404

    return jsonify({
        "ok": True,
        "key": key.to_record()
    }), 200
