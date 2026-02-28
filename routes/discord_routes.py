from flask import Blueprint, request, jsonify
import requests
import os

from core.discord_service import get_user_info, get_all_roles

discord_bp = Blueprint("discord", __name__)

CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:5000/callback"

# ---------------------------------------------------------
# CONFIG: PHP BASE URL (CHANGE ONLY THIS)
# ---------------------------------------------------------
PHP_BASE_URL = os.getenv("PHP_BASE_URL", "http://localhost:8000")
PHP_SYNC_URL = f"{PHP_BASE_URL}/admin/perks/sync_roles"


# ---------------------------------------------------------
# GET USER INFO
# ---------------------------------------------------------
@discord_bp.post("/get_user")
def get_user():
    discord_id = request.json.get("discord_id")
    return jsonify(get_user_info(discord_id))


# ---------------------------------------------------------
# GET ROLES (LIVE FROM DISCORD)
# ---------------------------------------------------------
@discord_bp.get("/get_roles")
def get_roles():
    return jsonify({"ok": True, "roles": get_all_roles()})


# ---------------------------------------------------------
# RECEIVE ROLES FROM PYTHON BOT → FORWARD TO PHP
# ---------------------------------------------------------
@discord_bp.post("/sync_roles")
def sync_roles():
    data = request.get_json()
    roles = data.get("roles", [])

    print("\n[PYTHON → FLASK] Received roles from bot:")
    print(roles)

    print(f"[FLASK → PHP] Forwarding to: {PHP_SYNC_URL}")

    try:
        php_response = requests.post(
            PHP_SYNC_URL,
            json={"roles": roles},
            timeout=5
        )

        print("[PHP RESPONSE]:", php_response.text)

        return jsonify({
            "ok": True,
            "received": len(roles),
            "php_response": php_response.text
        })

    except Exception as e:
        print("[ERROR] Could not send roles to PHP:", e)
        return jsonify({"ok": False, "error": str(e)}), 500


# ---------------------------------------------------------
# DISCORD OAUTH2 CALLBACK
# ---------------------------------------------------------
@discord_bp.get("/callback")
def callback():
    code = request.args.get("code")

    if not code:
        return jsonify({"error": "No code provided"}), 400

    token_response = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    token_json = token_response.json()
    access_token = token_json.get("access_token")

    if not access_token:
        return jsonify({"error": "Failed to get access token", "details": token_json}), 400

    user_response = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    return jsonify(user_response.json())
