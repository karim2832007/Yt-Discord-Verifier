from flask import Blueprint, jsonify
from app.services.user_service import UserService

bp = Blueprint("user", __name__)

@bp.get("/<int:user_id>")
def get_user(user_id):
    user = UserService.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "email": user.email,
        "username": user.username
    })