from flask import Blueprint, request, jsonify
from app.services.user_service import UserService
from app.security.auth import Auth

bp = Blueprint("auth", __name__)

@bp.post("/register")
def register():
    data = request.json
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if UserService.get_user_by_email(email):
        return jsonify({"error": "Email already exists"}), 400

    password_hash = Auth.hash_password(password)
    user = UserService.create_user(email, username, password_hash)

    token = Auth.create_token(user.id)
    return jsonify({"token": token, "user": {"id": user.id, "email": user.email}})

@bp.post("/login")
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = UserService.get_user_by_email(email)
    if not user or not Auth.verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    token = Auth.create_token(user.id)
    return jsonify({"token": token, "user": {"id": user.id, "email": user.email}})

@bp.get("/me")
def me():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return jsonify({"error": "Missing token"}), 401

    # Accept both:
    # "Bearer <token>"
    # "<token>"
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    else:
        token = auth_header

    user_id = Auth.verify_token(token)

    if not user_id:
        return jsonify({"error": "Invalid token"}), 401

    user = UserService.get_user_by_id(user_id)
    return jsonify({
        "id": user.id,
        "email": user.email,
        "username": user.username
    })
