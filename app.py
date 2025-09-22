from flask import Flask, redirect, request, session, jsonify, render_template_string, url_for
import os
import time
import secrets
import string
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

BASE_URL = os.environ["BASE_URL"].rstrip("/")

YOUTUBE_CHANNEL_ID = os.environ["YOUTUBE_CHANNEL_ID"]

GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
GOOGLE_REDIRECT = os.environ["GOOGLE_REDIRECT"]

DISCORD_CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
DISCORD_CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
DISCORD_REDIRECT = os.environ["DISCORD_REDIRECT"]
DISCORD_GUILD_ID = os.environ["DISCORD_GUILD_ID"]
DISCORD_ROLE_ID = os.environ["DISCORD_ROLE_ID"]
DISCORD_BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]

CODE_TTL = 15 * 60          # OAuth session state TTL in seconds
ACTIVATION_TTL = 24 * 60 * 60  # Activation validity: 24 hours

# --------------------------
# Helpers
# --------------------------

def now() -> int:
    return int(time.time())

def gen_code(n: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))

def is_expired(ts: int) -> bool:
    return now() - ts > CODE_TTL

def require_session_fields(*keys) -> bool:
    return all(k in session and session[k] is not None for k in keys)

def activation_expired(activated_at: int | None) -> bool:
    if not activated_at:
        return True
    return (now() - activated_at) >= ACTIVATION_TTL

def _success_page():
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Success</title>
<style>body,html{width:100%;height:100%;margin:0;background:#000;color:#0f0;display:flex;
align-items:center;justify-content:center;font-family:'Segoe UI',sans-serif;}
.box{text-align:center;}.msg{font-size:2rem;text-shadow:0 0 10px #0f0;}</style></head>
<body><div class="box"><p class="msg">✅ Success! Role has been assigned.</p><p>You can close this tab.</p></div></body></html>"""

def _error_page():
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error</title>
<style>body,html{width:100%;height:100%;margin:0;background:#000;color:#f00;display:flex;
align-items:center;justify-content:center;font-family:'Segoe UI',sans-serif;}
.box{text-align:center;}.msg{font-size:2rem;text-shadow:0 0 10px #f00;}</style></head>
<body><div class="box"><p class="msg">❌{{message}}</p><p>Please try again or contact support.</p></div></body></html>"""

# --------------------------
# Landing
# --------------------------

@app.route("/")
def home():
    session.clear()
    return render_template_string("""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>GamingMods Membership</title>
<link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
<style>
body,html{width:100%;height:100%;margin:0;background:#0a0a0a;color:#eee;
display:flex;align-items:center;justify-content:center;font-family:'Segoe UI',sans-serif;}
.hero-title{font-size:4rem;font-weight:bold;font-style:italic;color:#FFD700;text-shadow:0 0 10px #B8860B;}
.cta-btn{margin-top:2rem;padding:1rem 2rem;font-size:1.2rem;font-weight:bold;background:rgba(255,255,255,0.1);
color:#fff;border:2px solid #fff;border-radius:8px;cursor:pointer;}
.cta-btn:hover{transform:scale(1.05);}
.note{margin-top:1rem;color:#aaa;font-size:0.95rem;}
</style></head>
<body><div>
    <h1 class="hero-title">GamingMods</h1>
    <p>Unlock cheat engines, gallery tools, and exclusive mod features through YouTube + Discord integration.</p>
    <button class="cta-btn" onclick="window.location='{{ google_url }}'">Login with Google</button>
    <p class="note">After Google, you’ll be redirected to Discord to join and receive your role.</p>
</div></body></html>""",
    google_url=f"{BASE_URL}/google/login")

# --------------------------
# Google OAuth (YouTube subscription check)
# --------------------------

@app.route("/google/login")
def google_login():
    code = gen_code()
    session.clear()
    session["code"] = code
    session["created"] = now()
    session["status"] = "pending"
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT}"
        "&scope=https://www.googleapis.com/auth/youtube.readonly"
        "&response_type=code&access_type=online&prompt=consent"
        f"&state={code}"
    )
    return redirect(auth_url)

@app.route("/google/callback")
def google_callback():
    if not require_session_fields("code", "created", "status") or is_expired(session["created"]):
        return "Session expired", 400
    if request.args.get("state") != session["code"]:
        return "Invalid state", 400

    code_param = request.args.get("code")
    if not code_param:
        return "Google auth failed", 400

    token_req = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code_param,
            "redirect_uri": GOOGLE_REDIRECT,
            "grant_type": "authorization_code",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    ).json()

    if "access_token" not in token_req:
        return "Google auth failed", 400

    headers = {"Authorization": f"Bearer {token_req['access_token']}"}
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
        return render_template_string(_error_page(), message="YouTube subscription not found.")
    session["status"] = "yt_ok"
    return redirect(f"{BASE_URL}/discord/login")

# --------------------------
# Discord OAuth (join + role assignment)
# --------------------------

@app.route("/discord/login")
def discord_login():
    if session.get("status") != "yt_ok":
        return "Verify YouTube first", 400
    state = session["code"]
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT}"
        "&response_type=code"
        "&scope=identify%20guilds.join"
        f"&state={state}"
    )
    return redirect(auth_url)

@app.route("/discord/callback")
def discord_callback():
    if not require_session_fields("code", "created", "status") or is_expired(session["created"]):
        return render_template_string(_error_page(), message="Session expired.")
    if request.args.get("state") != session["code"]:
        return render_template_string(_error_page(), message="Invalid state.")

    code_param = request.args.get("code")
    if not code_param:
        return render_template_string(_error_page(), message="Discord auth failed.")

    token_req = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code_param,
            "redirect_uri": DISCORD_REDIRECT,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    ).json()

    if "access_token" not in token_req:
        return render_template_string(_error_page(), message="Discord auth failed.")

    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token_req['access_token']}"},
        timeout=20,
    ).json()

    if "id" not in user:
        return render_template_string(_error_page(), message="Failed to fetch Discord user.")

    bot_headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
    }

    # Join guild
    join_url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['id']}"
    requests.put(join_url, headers=bot_headers, json={"access_token": token_req["access_token"]}, timeout=20)

    # Assign role
    role_url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{user['id']}/roles/{DISCORD_ROLE_ID}"
    resp = requests.put(role_url, headers=bot_headers, timeout=20)

    if resp.status_code in (204, 201):
        # Store activation details in session
        session["status"] = "role_ok"
        session["discord_user_id"] = user["id"]
        session["activated_at"] = now()
        return render_template_string(_success_page())
    else:
        detail = {}
        if resp.headers.get("Content-Type", "").startswith("application/json"):
            try:
                detail = resp.json()
            except Exception:
                detail = {"error": resp.text}
        else:
            detail = {"error": resp.text}
        session["status"] = "role_failed"
        return render_template_string(_error_page(), message=f"Role assignment failed: {detail}")

# --------------------------
# Status endpoints
# --------------------------

@app.route("/status")
def status_me():
    if "status" not in session:
        return jsonify({"ok": False}), 404
    return jsonify({
        "ok": True,
        "status": session["status"],
        "code": session.get("code"),
        "expired": is_expired(session.get("created", 0)),
    }), 200

@app.route("/status/<code>")
def status_code(code):
    if session.get("code") != code:
        return jsonify({"ok": False}), 404
    return jsonify({"ok": True, "status": session["status"]}), 200

# --------------------------
# Verification endpoints for Ren'Py
# --------------------------

@app.route("/has_role_recent")
def has_role_recent():
    """
    Returns whether the current session has an active Gaming Mods role assignment,
    and respects the 24-hour activation TTL.
    """
    # Must have passed Discord role assignment previously
    role_ok = session.get("status") == "role_ok"
    activated_at = session.get("activated_at")

    if not role_ok or not activated_at:
        return jsonify({"ok": True, "has_role": False, "reason": "no_active_role"}), 200

    # Expiry check
    expired = activation_expired(activated_at)
    if expired:
        # Mark session as expired (optional)
        session["status"] = "expired"
        return jsonify({"ok": True, "has_role": False, "reason": "expired"}), 200

    # Return remaining time
    remaining = max(0, ACTIVATION_TTL - (now() - activated_at))
    return jsonify({
        "ok": True,
        "has_role": True,
        "activated_at": activated_at,
        "expires_in": remaining,
    }), 200

@app.route("/has_role/<discord_id>")
def has_role(discord_id):
    r = requests.get(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=20,
    )
    if r.status_code != 200:
        return jsonify({"ok": False, "error": "User not found"}), 404
    data = r.json()
    return jsonify({"ok": True, "has_role": DISCORD_ROLE_ID in data.get("roles", [])}), 200

# --------------------------
# Role removal (manual/cron)
# --------------------------

def remove_role_daily():
    bot_headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}
    r = requests.get(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000",
        headers=bot_headers,
        timeout=20,
    )
    try:
        members = r.json()
    except Exception:
        print("Parse error:", r.text)
        return
    if not isinstance(members, list):
        print("Unexpected format:", members)
        return

    removed = 0
    for m in members:
        if DISCORD_ROLE_ID in m.get("roles", []):
            u = m["user"]["id"]
            rr = requests.delete(
                f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{u}/roles/{DISCORD_ROLE_ID}",
                headers=bot_headers,
                timeout=20,
            )
            if rr.status_code == 204:
                removed += 1
    print(f"[RoleRemoval] Removed {removed} roles.")

@app.route("/remove_roles_now")
def remove_roles_now():
    remove_role_daily()
    return "Role removal triggered.", 200

# --------------------------
# Run
# --------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
