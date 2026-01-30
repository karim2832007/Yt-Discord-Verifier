from flask import Blueprint, request, jsonify
from app.services.nsfw_service import NSFWService
from flask import session

bp = Blueprint("nsfw", __name__)

@bp.post("/token")
def create_token():
    data = request.json
    user_id = data.get("user_id")
    token = data.get("token")
    expires_at = data.get("expires_at")

    t = NSFWService.create_token(user_id, token, expires_at)
    return jsonify({"id": t.id, "token": t.token})
