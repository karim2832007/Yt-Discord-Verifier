from flask import Flask, redirect, request, session, jsonify, render_template_string, make_response
import os
import time
import secrets
import string
import requests
import logging
from dotenv import load_dotenv

# ------------------------------------------------------------------------------
# Config and setup
# ------------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Base/branding
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
# YouTube
YOUTUBE_CHANNEL_ID = os.environ.get("YOUTUBE_CHANNEL_ID", "")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT = os.environ.get("GOOGLE_REDIRECT", "")
# Discord
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT = os.environ.get("DISCORD_REDIRECT", "")  # verifier callback
DISCORD_REDIRECT_SIMPLE = os.environ.get("DISCORD_REDIRECT_SIMPLE", "")  # site-login callback
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
# Admin panel key (for override endpoints)
ADMIN_PANEL_KEY = os.environ.get("ADMIN_PANEL_KEY", "")

# Settings
CODE_TTL = 15 * 60  # 15 minutes

# Override stores (in-memory)
global_override = False
admin_overrides = {}  # { discord_id(str): True }

# Logging
logging.basicConfig(level=logging.INFO)
app.config["PROPAGATE_EXCEPTIONS"] = True


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def now() -> int:
    return int(time.time())


def gen_code(n=6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))


def is_expired(created_ts: int) -> bool:
    try:
        return now() - int(created_ts) > CODE_TTL
    except Exception:
        return True


def require_session_fields(*keys) -> bool:
    return all(k in session and session[k] is not None for k in keys)


def require_admin_key() -> bool:
    key = request.args.get("key")
    return bool(ADMIN_PANEL_KEY) and key == ADMIN_PANEL_KEY


def google_exchange_token(code: str) -> dict:
    resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "redirect_uri": GOOGLE_REDIRECT,
            "grant_type": "authorization_code",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    return resp.json()


def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    resp = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    return resp.json()


def discord_get_user(access_token: str) -> dict:
    resp = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20,
    )
    return resp.json()


def discord_get_member(discord_id: str) -> dict:
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=20,
    )
    if resp.status_code == 200:
        return resp.json()
    return {"status_code": resp.status_code, "error": resp.text}


def discord_add_role(discord_id: str) -> bool:
    # Best effort: assign role after verification. Requires bot permissions and the user in guild.
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}/roles/{DISCORD_ROLE_ID}"
    resp = requests.put(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=20,
    )
    return resp.status_code in (204, 200)


def discord_has_role(member_json: dict) -> bool:
    roles = member_json.get("roles", [])
    return str(DISCORD_ROLE_ID) in [str(r) for r in roles]


def set_session_user(discord_id: str, username: str = "", discriminator: str = ""):
    session["user"] = {
        "id": str(discord_id),
        "username": username,
        "discriminator": discriminator,
        "ts": now(),
    }


# ------------------------------------------------------------------------------
# Error handler
# ------------------------------------------------------------------------------
@app.errorhandler(Exception)
def on_error(e):
    logging.exception("Unhandled exception in route:")
    return jsonify({"ok": False, "error": str(e)}), 500


# ------------------------------------------------------------------------------
# Home (verifier entry)
# ------------------------------------------------------------------------------
@app.route("/")
def home():
    # Start a fresh flow with a new code
    code = gen_code()
    session.clear()
    session["code"] = code
    session["created"] = now()
    session["status"] = "pending"

    return render_template_string(
        """
        <h2>YouTube → Discord verification</h2>
        <p>Your code: <b>{{code}}</b></p>
        <p>This code expires in 15 minutes.</p>
        <a href="{{google_url}}">Login with Google</a>
        """,
        code=code,
        google_url=f"{BASE_URL}/google/login" if BASE_URL else "/google/login",
    )


# ------------------------------------------------------------------------------
# Google OAuth (YouTube subscription check)
# ------------------------------------------------------------------------------
@app.route("/google/login")
def google_login():
    if not require_session_fields("code", "created", "status"):
        return "Invalid session", 400
    if is_expired(session["created"]):
        return "Session expired", 400

    code = session["code"]
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT}"
        f"&scope=https://www.googleapis.com/auth/youtube.readonly"
        f"&response_type=code&access_type=online&prompt=consent"
        f"&state={code}"
    )
    return redirect(auth_url)


@app.route("/google/callback")
def google_callback():
    if not require_session_fields("code", "created", "status"):
        return "Session expired", 400
    if is_expired(session["created"]):
        return "Session expired", 400

    # CSRF/state guard
    state = request.args.get("state")
    if not state or state != session["code"]:
        return "Invalid state", 400

    code_param = request.args.get("code")
    if not code_param:
        return "Google auth failed", 400

    token = google_exchange_token(code_param)
    if "access_token" not in token:
        return "Google auth failed", 400

    headers = {"Authorization": f"Bearer {token['access_token']}"}
    url = "https://www.googleapis.com/youtube/v3/subscriptions"
    params = {"part": "snippet", "mine": "true", "maxResults": 50}

    subscribed = False
    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=20).json()
        for item in resp.get("items", []):
            res = item.get("snippet", {}).get("resourceId", {})
            if res.get("channelId") == YOUTUBE_CHANNEL_ID:
                subscribed = True
                break
        if subscribed or "nextPageToken" not in resp:
            break
        params["pageToken"] = resp["nextPageToken"]

    if not subscribed:
        session["status"] = "failed"
        return "Not subscribed.", 400

    session["status"] = "yt_ok"
    # Continue to Discord login (verifier flow)
    return redirect(f"{BASE_URL}/discord/login" if BASE_URL else "/discord/login")


# ------------------------------------------------------------------------------
# Discord OAuth (verifier flow; requires YouTube first)
# ------------------------------------------------------------------------------
@app.route("/discord/login")
def discord_login():
    if not require_session_fields("code", "created", "status"):
        return "Session expired", 400
    if is_expired(session["created"]):
        return "Session expired", 400
    if session["status"] != "yt_ok":
        return "Verify YouTube first", 400

    code = session["code"]
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        f"&response_type=code&scope=identify"
        f"&state={code}"
    )
    return redirect(auth_url)


@app.route("/discord/callback")
def discord_callback():
    if not require_session_fields("code", "created", "status"):
        return "Session expired", 400
    if is_expired(session["created"]):
        return "Session expired", 400

    # CSRF/state guard
    state = request.args.get("state")
    if not state or state != session["code"]:
        return "Invalid state", 400

    code_param = request.args.get("code")
    if not code_param:
        return "Discord auth failed", 400

    token = discord_exchange_token(code_param, DISCORD_REDIRECT)
    if "access_token" not in token:
        return "Discord auth failed", 400

    user = discord_get_user(token["access_token"])
    discord_id = str(user.get("id", ""))

    if not discord_id:
        return "Discord user not found", 400

    # Best effort: try to add role
    added = discord_add_role(discord_id)
    set_session_user(discord_id, user.get("username", ""), user.get("discriminator", ""))

    msg = "Verification complete."
    if added:
        msg = "Verification complete. Role assigned."
    return render_template_string(
        """
        <h3>{{msg}}</h3>
        <p>Discord ID: <b>{{discord_id}}</b></p>
        <script>
        // After brief pause, send users back to the main site
        setTimeout(function(){ window.location.href = "https://gaming-mods.com/"; }, 1200);
        </script>
        """,
        msg=msg,
        discord_id=discord_id,
    )


# ------------------------------------------------------------------------------
# Discord OAuth (site-login flow; standalone login from gaming-mods.com)
# ------------------------------------------------------------------------------
@app.route("/login/discord")
def discord_login_simple():
    # Site login does not require YouTube; fresh state for CSRF
    code = gen_code()
    session["simple_code"] = code
    session["simple_created"] = now()

    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_SIMPLE}"
        f"&response_type=code&scope=identify"
        f"&state={code}"
    )
    return redirect(auth_url)


@app.route("/login/discord/callback")
def discord_login_simple_callback():
    if not require_session_fields("simple_code", "simple_created"):
        return "Session expired", 400
    if is_expired(session["simple_created"]):
        return "Session expired", 400

    state = request.args.get("state")
    if not state or state != session["simple_code"]:
        return "Invalid state", 400

    code_param = request.args.get("code")
    if not code_param:
        return "Discord auth failed", 400

    token = discord_exchange_token(code_param, DISCORD_REDIRECT_SIMPLE)
    if "access_token" not in token:
        return "Discord auth failed", 400

    user = discord_get_user(token["access_token"])
    discord_id = str(user.get("id", ""))

    if not discord_id:
        return "Discord user not found", 400

    set_session_user(discord_id, user.get("username", ""), user.get("discriminator", ""))

    # Show a quick confirmation with ID, then send back to homepage
    html = f"""
    <h3>Login successful</h3>
    <p>Your Discord ID: <b>{discord_id}</b></p>
    <script>
    alert("Logged in! Your Discord ID is {discord_id}");
    window.location.href = "https://gaming-mods.com/index.html";
    </script>
    """
    resp = make_response(html)
    return resp


# ------------------------------------------------------------------------------
# Status: combine role check with overrides
# ------------------------------------------------------------------------------
@app.route("/status/<discord_id>")
def status(discord_id):
    # Overrides short-circuit to granted
    if global_override:
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "⚡ Global admin override active",
        }), 200

    if admin_overrides.get(str(discord_id)):
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "⚡ Admin override active",
        }), 200

    # Normal path: check member + role
    member = discord_get_member(str(discord_id))
    if "roles" in member:
        has = discord_has_role(member)
        return jsonify({
            "ok": True,
            "role_granted": bool(has),
            "message": "Subscriber role verified." if has else "Subscriber role not found.",
        }), 200
    else:
        # member not found or error
        status_code = member.get("status_code", 404)
        return jsonify({
            "ok": False,
            "role_granted": False,
            "message": f"Member not found or error (HTTP {status_code}).",
        }), 404


# ------------------------------------------------------------------------------
# Admin override endpoints
# ------------------------------------------------------------------------------
@app.route("/override/all", methods=["GET", "POST", "DELETE"])
def override_all():
    global global_override
    if request.method == "GET":
        return jsonify({"ok": True, "global_override": global_override}), 200

    if not require_admin_key():
        return jsonify({"ok": False, "message": "Forbidden."}), 403

    if request.method == "POST":
        global_override = True
        return jsonify({"ok": True, "message": "Global override enabled"}), 200
    elif request.method == "DELETE":
        global_override = False
        return jsonify({"ok": True, "message": "Global override disabled"}), 200

    return jsonify({"ok": False, "message": "Method not allowed"}), 405


@app.route("/override/<discord_id>", methods=["GET", "POST", "DELETE"])
def override_user(discord_id):
    did = str(discord_id)

    if request.method == "GET":
        active = bool(admin_overrides.get(did))
        return jsonify({"ok": True, "user_override": active, "discord_id": did}), 200

    if not require_admin_key():
        return jsonify({"ok": False, "message": "Forbidden."}), 403

    if request.method == "POST":
        admin_overrides[did] = True
        return jsonify({"ok": True, "message": f"Override enabled for {did}"}), 200
    elif request.method == "DELETE":
        admin_overrides.pop(did, None)
        return jsonify({"ok": True, "message": f"Override disabled for {did}"}), 200

    return jsonify({"ok": False, "message": "Method not allowed"}), 405


# Optional: list all per-user overrides (admin key required)
@app.route("/override", methods=["GET"])
def list_overrides():
    if not require_admin_key():
        return jsonify({"ok": False, "message": "Forbidden."}), 403
    return jsonify({"ok": True, "global_override": global_override, "users": list(admin_overrides.keys())}), 200


# ------------------------------------------------------------------------------
# Session helpers
# ------------------------------------------------------------------------------
@app.route("/portal/me")
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({"ok": True, "user": user}), 200


@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True, "message": "Logged out"}), 200


# ------------------------------------------------------------------------------
# Health
# ------------------------------------------------------------------------------
@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": now()}), 200


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)