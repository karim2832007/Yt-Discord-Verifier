from flask import Flask, redirect, request, session, jsonify, render_template_string
import os
import time
import secrets
import string
import requests
import logging
import hmac
import hashlib
import base64
from dotenv import load_dotenv

# ------------------------------------------------------------------------------
# Config and setup
# ------------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Main site URL (for post-login redirect)
MAIN_SITE_URL = os.environ.get("MAIN_SITE_URL", "https://gaming-mods.com").rstrip("/")

# Discord OAuth
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
# Note: You can register one or both in the Discord Developer Portal:
# - https://verifier.gaming-mods.com/login/discord/callback
# - https://verifier.gaming-mods.com/discord/callback
# For the token exchange, we'll use request.base_url to match the callback actually hit.
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")

# Admin panel key (for override endpoints)
ADMIN_PANEL_KEY = os.environ.get("ADMIN_PANEL_KEY", "")

# Settings
STATE_TTL = 15 * 60   # 15 minutes window for OAuth state

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


def sign_state(payload: str) -> str:
    """Create HMAC-SHA256 signature and produce a compact token: base64(payload|sig)."""
    key = app.secret_key.encode("utf-8")
    sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).digest()
    token = f"{payload}|{base64.urlsafe_b64encode(sig).decode('utf-8')}"
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("utf-8")


def verify_state(token: str) -> bool:
    """Verify token integrity and TTL."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        payload, sig_b64 = raw.split("|", 1)
        nonce, ts_str = payload.split(".", 1)
        ts = int(ts_str)
        if now() - ts > STATE_TTL:
            return False
        key = app.secret_key.encode("utf-8")
        expected_sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).digest()
        given_sig = base64.urlsafe_b64decode(sig_b64.encode("utf-8"))
        return hmac.compare_digest(expected_sig, given_sig)
    except Exception:
        return False


def make_state() -> str:
    """Generate stateless state token with nonce + timestamp, HMAC-signed."""
    payload = f"{secrets.token_hex(8)}.{now()}"
    return sign_state(payload)


def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    """Exchange Discord auth code for access token; redirect_uri must match the callback URL that was hit."""
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


def discord_has_role(member_json: dict) -> bool:
    roles = member_json.get("roles", [])
    return str(DISCORD_ROLE_ID) in [str(r) for r in roles]


def discord_add_role(discord_id: str) -> bool:
    """Assign the verification role (best effort). Requires the user to be in the guild and the bot to have permissions."""
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}/roles/{DISCORD_ROLE_ID}"
    resp = requests.put(
        url,
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        timeout=20,
    )
    return resp.status_code in (204, 200)


def should_assign_role_on_login(discord_id: str) -> bool:
    """Role assignment policy on login:
       - If global override is ON: assign role for anyone who logs in.
       - Else if per-user override is ON for this ID: assign role for this user.
       - Else: do NOT auto-assign; normal users keep their existing roles.
    """
    if global_override:
        return True
    return bool(admin_overrides.get(str(discord_id)))


def require_admin_key() -> bool:
    key = request.args.get("key")
    return bool(ADMIN_PANEL_KEY) and key == ADMIN_PANEL_KEY


# ------------------------------------------------------------------------------
# Error handler
# ------------------------------------------------------------------------------
@app.errorhandler(Exception)
def on_error(e):
    logging.exception("Unhandled exception in route:")
    return jsonify({"ok": False, "error": str(e)}), 500


# ------------------------------------------------------------------------------
# Minimal home
# ------------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template_string(
        """
        <h2>Discord Login</h2>
        <p>This backend handles Discord OAuth and admin overrides.</p>
        <a href="/login/discord">Login with Discord</a>
        """
    )


# ------------------------------------------------------------------------------
# Discord OAuth (standalone site login — no Google required)
# ------------------------------------------------------------------------------
@app.route("/login/discord")
def discord_login():
    # Stateless CSRF state token
    state = make_state()
    # IMPORTANT: The callback used by Discord can be either of these (register them in the Developer Portal):
    # - https://verifier.gaming-mods.com/login/discord/callback
    # - https://verifier.gaming-mods.com/discord/callback
    # For authorization, pick the first one by default; token exchange will use the actual callback URL hit.
    redirect_uri = f"{request.url_root.rstrip('/')}/login/discord/callback"
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code&scope=identify"
        f"&state={state}"
    )
    return redirect(auth_url)


def _discord_callback_core():
    """Shared logic for both callback paths. Uses request.base_url as redirect_uri for token exchange."""
    state = request.args.get("state")
    code_param = request.args.get("code")

    if not state or not verify_state(state):
        return "Invalid or expired state", 400
    if not code_param:
        return "Discord auth failed", 400

    # Use the exact URL of the callback that was hit, matching the registered URI.
    redirect_uri_used = request.base_url

    token = discord_exchange_token(code_param, redirect_uri_used)
    if "access_token" not in token:
        return "Discord auth failed", 400

    user = discord_get_user(token["access_token"])
    discord_id = str(user.get("id", "")) or ""
    if not discord_id:
        return "Discord user not found", 400

    # Role assignment based on override policy
    assigned = False
    try:
        if should_assign_role_on_login(discord_id):
            assigned = discord_add_role(discord_id)
    except Exception:
        assigned = False

    # Set a lightweight session for /portal/me (cookie tied to verifier domain)
    session["user"] = {
        "id": discord_id,
        "username": user.get("username", ""),
        "discriminator": user.get("discriminator", ""),
        "ts": now(),
    }

    # Render an ID copy gate: user must click "Copy ID" before "Continue" becomes enabled.
    msg = "Login successful."
    role_msg = ""
    if global_override:
        role_msg = "Global override is active; your role may be assigned automatically."
    elif admin_overrides.get(discord_id):
        role_msg = "Admin override for your ID is active; your role may be assigned automatically."

    return render_template_string(
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Confirm Your Discord ID</title>
          <style>
            body { background:#0a0a0a; color:#eee; font-family:'Segoe UI',sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
            .card { background:rgba(0,0,0,0.6); padding:2rem; border-radius:12px; box-shadow:0 0 20px rgba(0,0,0,0.7); text-align:center; max-width:520px; }
            h2 { color:#FFD700; text-shadow:0 0 10px #B8860B; margin-bottom:0.5rem; }
            p { color:#ccc; }
            .id { font-size:1.25rem; margin:1rem 0; color:#fff; }
            .row { margin-top:1.25rem; display:flex; gap:.75rem; justify-content:center; }
            button {
              padding:.75rem 1.25rem; border:none; border-radius:8px; cursor:pointer; font-weight:bold; color:#fff; background:#111;
              box-shadow:0 0 10px #444; transition:transform .2s, box-shadow .2s;
            }
            button:hover { transform:scale(1.04); box-shadow:0 0 20px #666; }
            button.primary { box-shadow:0 0 10px #0f0; }
            button.disabled { opacity:.6; cursor:not-allowed; box-shadow:none; }
            .hint { font-size:.9rem; color:#999; margin-top:0.75rem; }
            .ok { color:#8ef18e; margin-top:0.5rem; display:none; }
          </style>
        </head>
        <body>
          <div class="card">
            <h2>{{ msg }}</h2>
            {% if role_msg %}<p>{{ role_msg }}</p>{% endif %}
            {% if assigned %}<p class="ok">Role assigned successfully.</p>{% endif %}
            <p class="id">Your Discord ID: <b id="did">{{ discord_id }}</b></p>
            <div class="row">
              <button id="copy" class="primary">Copy ID</button>
              <button id="continue" class="disabled" disabled>Continue</button>
            </div>
            <p class="hint">You need to copy your ID before continuing.</p>
          </div>

          <script>
            const did = document.getElementById("did").textContent.trim();
            const copyBtn = document.getElementById("copy");
            const contBtn = document.getElementById("continue");
            const okMsg = document.querySelector(".ok");

            copyBtn.addEventListener("click", async () => {
              try {
                await navigator.clipboard.writeText(did);
                copyBtn.textContent = "Copied!";
                contBtn.classList.remove("disabled");
                contBtn.removeAttribute("disabled");
                if (okMsg) okMsg.style.display = "block";
              } catch (e) {
                alert("Copy failed. Please manually select and copy your ID.");
              }
            });

            contBtn.addEventListener("click", () => {
              if (contBtn.hasAttribute("disabled")) return;
              // Send back to index.html with the discord_id as a parameter
              window.location.href = "{{ main_url }}/index.html?discord_id=" + encodeURIComponent(did);
            });
          </script>
        </body>
        </html>
        """,
        msg=msg,
        role_msg=role_msg,
        assigned=assigned,
        discord_id=discord_id,
        main_url=MAIN_SITE_URL,
    )


# Two callback routes mapped to the same core logic (avoids 404 if either is used)
@app.route("/login/discord/callback")
def discord_callback_login_path():
    return _discord_callback_core()

@app.route("/discord/callback")
def discord_callback_plain_path():
    return _discord_callback_core()


# ------------------------------------------------------------------------------
# Status: combine role check with overrides
# ------------------------------------------------------------------------------
@app.route("/status/<discord_id>")
def status(discord_id):
    did = str(discord_id)

    # Overrides short-circuit to granted
    if global_override:
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "⚡ Global admin override active",
        }), 200

    if admin_overrides.get(did):
        return jsonify({
            "ok": True,
            "role_granted": True,
            "message": "⚡ Admin override active",
        }), 200

    # Normal path: check member + role
    member = discord_get_member(did)
    if "roles" in member:
        has = discord_has_role(member)
        return jsonify({
            "ok": True,
            "role_granted": bool(has),
            "message": "Subscriber role verified." if has else "Subscriber role not found.",
        }), 200

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

    if request.method == "DELETE":
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

    if request.method == "DELETE":
        admin_overrides.pop(did, None)
        return jsonify({"ok": True, "message": f"Override disabled for {did}"}), 200

    return jsonify({"ok": False, "message": "Method not allowed"}), 405


@app.route("/override", methods=["GET"])
def list_overrides():
    if not require_admin_key():
        return jsonify({"ok": False, "message": "Forbidden."}), 403
    return jsonify({
        "ok": True,
        "global_override": global_override,
        "users": list(admin_overrides.keys())
    }), 200


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