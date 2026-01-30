from flask import Blueprint, request, jsonify
from app.services.discord_service import DiscordService
from app.services.user_service import UserService
from flask import session


bp = Blueprint("discord", __name__)

@bp.post("/link")
def link():
    data = request.json
    user_id = data.get("user_id")
    discord_id = data.get("discord_id")
    username = data.get("username")
    avatar = data.get("avatar")
    roles = data.get("roles")

    user = UserService.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    DiscordService.link_discord(user, discord_id, username, avatar, roles)
    return jsonify({"status": "linked"})
