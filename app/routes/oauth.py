import uuid
import requests
from flask import Blueprint, redirect, request, session, jsonify, current_app as app

from ..oauth import safe_token_exchange   # OAuth utility logic

bp = Blueprint("oauth", __name__)

OAUTH_STATE_KEY = "discord_oauth_state"


def _build_redirect_uri():
    # Use the instance config (app.cfg), not the class
    return app.cfg.DISCORD_REDIRECT_URI


# -----------------------------
# 1. Redirect user to Discord
# -----------------------------
@bp.route("/login/discord", methods=["GET"])
def login_discord():
    state = uuid.uuid4().hex
    session[OAUTH_STATE_KEY] = state

    params = {
        "client_id": app.cfg.DISCORD_CLIENT_ID,
        "redirect_uri": _build_redirect_uri(),
        "response_type": "code",
        "scope": "identify email",
        "state": state,
        "disable_mobile_redirect": "true"   # prevents Discord app hijacking
    }

    url = (
        f"{app.cfg.DISCORD_API_BASE}/oauth2/authorize?"
        + "&".join([f"{k}={requests.utils.requote_uri(str(v))}" for k, v in params.items()])
    )

    return redirect(url)


# -----------------------------
# 2. Discord callback
# -----------------------------
@bp.route("/login/discord/callback", methods=["GET"])
def login_discord_callback():
    error = request.args.get("error")
    if error:
        return jsonify({"ok": False, "error": "oauth_error", "message": error}), 400

    code = request.args.get("code")
    state = request.args.get("state")
    saved_state = session.pop(OAUTH_STATE_KEY, None)

    if not code or not state or saved_state != state:
        return jsonify({
            "ok": False,
            "error": "invalid_state",
            "message": "State mismatch or missing code"
        }), 400

    token_url = f"{app.cfg.DISCORD_API_BASE}/oauth2/token"
    data = {
        "client_id": app.cfg.DISCORD_CLIENT_ID,
        "client_secret": app.cfg.DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _build_redirect_uri(),
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        token_json = safe_token_exchange(token_url, data, headers, logger=app.logger_custom)
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": "token_exchange_failed",
            "message": str(e)
        }), 502

    access_token = token_json.get("access_token")
    if not access_token:
        return jsonify({
            "ok": False,
            "error": "no_access_token",
            "message": token_json
        }), 502

    # Fetch Discord user info
    try:
        user_resp = requests.get(
            f"{app.cfg.DISCORD_API_BASE}/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=8
        )
        user_resp.raise_for_status()
        user_json = user_resp.json()
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": "user_fetch_failed",
            "message": str(e)
        }), 502

    # Extract Discord user fields
    user_id = user_json.get("id")
    username = user_json.get("username")

    # Store ONLY what the frontend needs
    session["user"] = {
        "id": str(user_id),
        "discord_id": str(user_id),
        "username": username
    }

    next_url = session.pop("next", None) or "https://gaming-mods.com/"
    return redirect(next_url)


# -----------------------------
# 3. Return logged-in user info
# -----------------------------
@bp.route("/portal/me", methods=["GET"])
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not authenticated"}), 401

    return jsonify({
        "ok": True,
        "user_id": user.get("id"),
        "discord_id": user.get("discord_id"),
        "username": user.get("username"),
        "user": {
            "id": user.get("id"),
            "discord_id": user.get("discord_id"),
            "username": user.get("username")
        }
    }), 200
