from flask import Blueprint, request, jsonify, session, make_response
from datetime import datetime, timedelta
from app.extensions import db
from app.models.key import Key
from app.security.auth import Auth
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
    # GET: Auto-generate quick key + SHOW HTML PAGE
    # -----------------------------------------------------

    # Try session first
    if "user" in session and session["user"].get("id"):
        user_id = session["user"]["id"]
    else:
        # Try Authorization header
        auth_header = request.headers.get("Authorization")
        token = None

        if auth_header:
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]
            else:
                token = auth_header

        # Try ?token=
        if not token:
            token = request.args.get("token")

        # Decode token
        user_id = Auth.verify_token(token) if token else None

        # Final fallback
        if not user_id:
            user_id = "anonymous"

    key = create_key_record(user_id=user_id)

    # -----------------------------------------------------
    # Return a simple HTML page with the key
    # -----------------------------------------------------
    html = f"""
    <html>
        <head>
            <title>Your Game Key</title>
            <style>
                body {{
                    background: #0d0d0d;
                    color: #00eaff;
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding-top: 80px;
                }}
                .box {{
                    background: #111;
                    padding: 30px;
                    border-radius: 10px;
                    display: inline-block;
                    border: 2px solid #00eaff;
                }}
                .key {{
                    font-size: 28px;
                    font-weight: bold;
                    margin-top: 20px;
                }}
                .note {{
                    margin-top: 20px;
                    font-size: 16px;
                    color: #ccc;
                }}
                a {{
                    color: #00eaff;
                    text-decoration: none;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <div class="box">
                <h1>Your Key Has Been Generated</h1>
                <div class="key">{key.key_value}</div>
                <div class="note">
                    Copy your key now.  
                    After that, you can return to the main site.
                </div>
                <br>
                <a href="https://gaming-mods.com">Go back to Gaming-Mods</a>
            </div>
        </body>
    </html>
    """

    response = make_response(html)
    response.headers["Content-Type"] = "text/html"
    return response
