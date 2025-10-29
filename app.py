# app.py — Part 1/6
import os
import time
import secrets
import hmac
import hashlib
import base64
import logging
import json
from datetime import timedelta

import requests
from flask import (
    Flask, redirect, request, session, jsonify,
    render_template_string, send_from_directory
)
from flask_cors import CORS
from dotenv import load_dotenv

# -----------------------------------------------------------------------------
# App config
# -----------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=1)

SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", None)
app.config.update(
    SESSION_COOKIE_DOMAIN=SESSION_COOKIE_DOMAIN,
    SESSION_COOKIE_SECURE=True,       # requires HTTPS
    SESSION_COOKIE_SAMESITE="None",   # allows cross-site OAuth
    PROPAGATE_EXCEPTIONS=True,
)

BASE_URL = os.environ.get("BASE_URL", "https://gaming-mods.com").rstrip("/")
IONOS_INDEX = f"{BASE_URL}/index.html"
IONOS_ADMIN = f"{BASE_URL}/admin.html"
IONOS_GAMES = f"{BASE_URL}/games.html"
IONOS_DONATE = f"{BASE_URL}/donate.html"
IONOS_PRIVACY = f"{BASE_URL}/privacy.html"

CORS(app, origins=[BASE_URL], supports_credentials=True)

# -----------------------------------------------------------------------------
# Discord & owner env
# -----------------------------------------------------------------------------
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
OWNER_ID = os.environ.get("OWNER_ID", "")
DISCORD_REDIRECT = os.environ.get("DISCORD_REDIRECT", "").strip()

# -----------------------------------------------------------------------------
# State (persisted override & login history)
# -----------------------------------------------------------------------------
global_override = False
admin_overrides = {}
login_history = []
STATE_FILE = "override_state.json"
STATE_TTL = 15 * 60  # state validity in seconds

def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({"global_override": global_override, "admin_overrides": admin_overrides}, f)
    except Exception:
        logging.exception("Failed to save state")

def load_state():
    global global_override, admin_overrides
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE) as f:
                data = json.load(f)
                global_override = data.get("global_override", False)
                admin_overrides = data.get("admin_overrides", {})
    except Exception:
        logging.exception("Failed to load state")

load_state()

# app.py — Part 2/6
# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)

def now_ts() -> int:
    return int(time.time())

def sign_state(payload: str) -> str:
    key = app.secret_key.encode()
    sig = hmac.new(key, payload.encode(), hashlib.sha256).digest()
    token = f"{payload}|{base64.urlsafe_b64encode(sig).decode()}"
    return base64.urlsafe_b64encode(token.encode()).decode()

def verify_state(token: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(token).decode()
        payload, sig_b64 = raw.split("|", 1)
        _, ts_str = payload.split(".", 1)
        if now_ts() - int(ts_str) > STATE_TTL:
            return False
        key = app.secret_key.encode()
        expected = hmac.new(key, payload.encode(), hashlib.sha256).digest()
        given = base64.urlsafe_b64decode(sig_b64)
        return hmac.compare_digest(expected, given)
    except Exception:
        return False

def make_state() -> str:
    payload = f"{secrets.token_hex(8)}.{now_ts()}"
    return sign_state(payload)

def require_owner() -> bool:
    user = session.get("user")
    return bool(user and OWNER_ID and str(user.get("id")) == str(OWNER_ID))

def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {}

UA = "GamingMods-Verifier/1.0 (+https://gaming-mods.com)"

# -----------------------------------------------------------------------------
# Rate-limit aware Discord helpers
# -----------------------------------------------------------------------------
def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    """
    Exchanges OAuth code for tokens. Handles 429 with backoff and returns
    structured error when Retry-After is large (so we can show a friendly page).
    """
    url = "https://discord.com/api/oauth2/token"
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": UA,
    }

    MAX_ATTEMPTS = 4
    BACKOFF_BASE = 0.5
    MAX_IN_REQUEST_SLEEP = 5

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = requests.post(url, data=data, headers=headers, timeout=15)
        except requests.RequestException as exc:
            logging.warning("token exchange network error (attempt %d): %s", attempt, exc)
            if attempt == MAX_ATTEMPTS:
                return {"error": "network_error", "message": str(exc)}
            time.sleep(min(BACKOFF_BASE * (2 ** (attempt - 1)), MAX_IN_REQUEST_SLEEP))
            continue

        if resp.status_code == 429:
            retry_after = None
            try:
                retry_after = int(resp.headers.get("Retry-After") or resp.headers.get("retry-after") or 0)
            except Exception:
                retry_after = None

            logging.warning("token exchange 429 (attempt %d), retry_after=%s", attempt, retry_after)

            if retry_after and retry_after > MAX_IN_REQUEST_SLEEP:
                return {
                    "error": "rate_limited",
                    "status": 429,
                    "retry_after": retry_after,
                    "body": resp.text,
                    "json": _safe_json(resp),
                }

            sleep_for = retry_after if (retry_after and retry_after > 0) else (BACKOFF_BASE * (2 ** (attempt - 1)))
            time.sleep(min(sleep_for, MAX_IN_REQUEST_SLEEP))
            continue

        if 500 <= resp.status_code < 600:
            logging.warning("token exchange server error %s (attempt %d)", resp.status_code, attempt)
            if attempt == MAX_ATTEMPTS:
                return {"error": "token_exchange_failed", "status": resp.status_code, "body": resp.text, "json": _safe_json(resp)}
            time.sleep(min(BACKOFF_BASE * (2 ** (attempt - 1)), MAX_IN_REQUEST_SLEEP))
            continue

        payload = _safe_json(resp)
        if resp.status_code != 200:
            logging.warning("token exchange bad status %s: %s", resp.status_code, resp.text)
            return {"error": "token_exchange_failed", "status": resp.status_code, "body": resp.text, "json": payload}

        return payload

    return {"error": "token_exchange_failed", "status": "max_retries_exceeded"}

# app.py — Part 3/6
def discord_get_user(token: str) -> dict:
    """
    Fetches /users/@me and handles 429 explicitly. Caller should branch
    UI when {'error': 'rate_limited'} is returned.
    """
    url = "https://discord.com/api/users/@me"
    headers = {"Authorization": f"Bearer {token}", "User-Agent": UA}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except Exception as e:
        return {"error": "user_fetch_failed", "message": str(e)}

    if resp.status_code == 429:
        retry_after = None
        try:
            retry_after = int(resp.headers.get("Retry-After") or resp.headers.get("retry-after") or 0)
        except Exception:
            retry_after = None
        return {"error": "rate_limited", "status": 429, "retry_after": retry_after, "body": resp.text}

    data = _safe_json(resp)
    if resp.status_code != 200:
        return {"error": "user_fetch_failed", "status": resp.status_code, "body": resp.text, "json": data}
    return data

def discord_member(did: str) -> dict:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN:
        return {"status_code": 400, "error": "missing_guild_or_bot_token"}
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}"
    resp = requests.get(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}, timeout=15)
    if resp.status_code == 200:
        return _safe_json(resp)
    return {"status_code": resp.status_code, "error": resp.text}

def discord_has_role(member: dict) -> bool:
    return str(DISCORD_ROLE_ID) in [str(r) for r in member.get("roles", [])]

def discord_add_role(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN or not DISCORD_ROLE_ID:
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    resp = requests.put(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}, timeout=15)
    return resp.status_code in (200, 204)

def discord_remove_role(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN or not DISCORD_ROLE_ID:
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    resp = requests.delete(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}, timeout=15)
    return resp.status_code in (200, 204)

# -----------------------------------------------------------------------------
# Error handler
# -----------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_exception(e):
    logging.exception("Unhandled exception:")
    return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/portal/me}")
def portal_me_redirect():
    # Redirect any accidental /portal/me} requests to the correct page
    return redirect("/portal/me", code=302)

@app.route("/favicon.ico")
def favicon():
    # Return empty 204 so browsers stop logging 500s
    return "", 204


import secrets, time, sqlite3
from flask import jsonify, session

DB_PATH = "keys.db"

# Ensure table exists
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS issued_keys (
                key TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
init_db()

def create_new_key(did: str):
    """Invalidate old keys for this DID and create a new one with 24h expiry."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM issued_keys WHERE did = ?", (did,))
        key = secrets.token_urlsafe(24)
        expires_at = time.time() + 24*60*60
        conn.execute("INSERT INTO issued_keys (key, did, expires_at) VALUES (?, ?, ?)",
                     (key, did, expires_at))
        conn.commit()
    return key

def get_key_record(key: str):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT did, expires_at FROM issued_keys WHERE key = ?", (key,)).fetchone()
        if row:
            return {"did": row[0], "expires_at": row[1]}
        return None

@app.route("/generate_key", methods=["POST"])
def generate_key_route():
    try:
        user = session.get("user")
        if not user:
            return jsonify({"ok": False, "message": "Not logged in"}), 401

        did = str(user.get("id"))
        username = user.get("username", "")

        new_key = create_new_key(did)
        return jsonify({
            "ok": True,
            "key": new_key,
            "message": f"Welcome {username}, here’s your new key."
        }), 200

    except Exception as e:
        app.logger.exception("Key generation failed")
        return jsonify({"ok": False, "message": f"Server error: {str(e)}"}), 500

@app.route("/validate_key/<did>/<key>")
def validate_key_route(did, key):
    try:
        record = get_key_record(key)
        if not record:
            return jsonify({"ok": False, "valid": False, "message": "Key not found"}), 400
        if record["did"] != did:
            return jsonify({"ok": False, "valid": False, "message": "Key does not belong to this ID"}), 403
        if time.time() > record["expires_at"]:
            return jsonify({"ok": False, "valid": False, "message": "Key expired"}), 410

        return jsonify({"ok": True, "valid": True, "message": "Key validated successfully"}), 200

    except Exception as e:
        app.logger.exception("Validation failed")
        return jsonify({"ok": False, "valid": False, "message": f"Server error: {str(e)}"}), 500

# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------

def create_new_key(did: str):
    """Generate and store a new key with 24h expiry for this Discord ID.
       Any old keys for this DID are invalidated immediately."""
    # Cleanup: remove any existing keys for this DID
    to_delete = [k for k, rec in issued_keys.items() if rec["did"] == did]
    for k in to_delete:
        issued_keys.pop(k, None)

    # Generate a fresh random key
    key = secrets.token_urlsafe(24)
    issued_keys[key] = {
        "did": did,
        "expires_at": time.time() + 24*60*60  # 24 hours from now
    }
    return key


# -----------------------------------------------------------------------------
# Serve id.js at same level as app.py
# -----------------------------------------------------------------------------
from flask import send_from_directory

@app.route("/id.js")
def serve_id_js():
    here = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(here, "id.js")  # ✅ fixed helper name

# app.py — Part 4/6
# -----------------------------------------------------------------------------
# Front-end redirects
# -----------------------------------------------------------------------------
@app.route("/")
def serve_index():
    return redirect(IONOS_INDEX)

@app.route("/admin")
def serve_admin():
    if not require_owner():
        return "Forbidden", 403
    return redirect(IONOS_ADMIN)

@app.route("/games")
def serve_games():
    return redirect(IONOS_GAMES)

@app.route("/privacy")
def serve_privacy():
    return redirect(IONOS_PRIVACY)

@app.route("/donate")
def serve_donate():
    return redirect(IONOS_DONATE)

@app.route("/admin/logins")
def admin_logins():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    return jsonify({"ok": True, "logins": login_history}), 200



issued_keys = {}

@app.route("/generate_key", methods=["POST"])
def generate_key():
    data = request.get_json(silent=True) or {}
    did = (data.get("discord_id") or "").strip()
    if not did:
        return jsonify({"ok": False, "message": "Missing Discord ID"}), 400

    key = secrets.token_urlsafe(16)
    issued_keys[key] = {"did": did, "used": False}
    return jsonify({"ok": True, "key": key, "message": "Key generated"}), 200

@app.route("/validate_key/<did>/<key>")
def validate_key_route(did, key):
    try:
        # 🔑 Admin override: accept anything
        if global_override or admin_overrides.get(did):
            return jsonify({
                "ok": True,
                "valid": True,
                "message": "ADMIN OVERRIDE ACTIVE – any key accepted"
            }), 200

        # Normal validation logic here...
        record = get_key_record(key)
        if not record:
            return jsonify({"ok": False, "valid": False, "message": "Key not found"}), 400
        if record["did"] != did:
            return jsonify({"ok": False, "valid": False, "message": "Key does not belong to this ID"}), 403
        if time.time() > record["expires_at"]:
            return jsonify({"ok": False, "valid": False, "message": "Key expired"}), 410

        return jsonify({"ok": True, "valid": True, "message": "Key validated successfully"}), 200
    except Exception as e:
        app.logger.exception("Validation failed")
        return jsonify({"ok": False, "valid": False, "message": f"Server error: {str(e)}"}), 500

# -----------------------------------------------------------------------------
# Mobile-friendly HTML snippets
# -----------------------------------------------------------------------------
MOBILE_CSS = """
:root{--bg:#0b0b0b;--card:#121212;--fg:#eee;--muted:#bbb;--accent:#d4af37;--btn:#1a73e8}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial;display:flex;min-height:100vh}
main{margin:auto;max-width:720px;width:100%;padding:16px}
.card{background:var(--card);border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,.45);padding:20px}
h1,h2{margin:0 0 10px;font-weight:700;font-size:22px}
p{margin:8px 0;color:var(--muted);line-height:1.5}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
a.button,button.button{appearance:none;border:none;border-radius:12px;background:var(--btn);color:#fff;padding:12px 16px;font-weight:700;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;min-width:140px}
a.alt,button.alt{background:var(--accent);color:#101010}
pre{background:#0a0a0a;color:#ddd;padding:10px;border-radius:10px;overflow:auto;max-height:200px}
.meta{font-family:ui-monospace,Consolas,Menlo,monospace;background:#0a0a0a;color:#ddd;padding:10px;border-radius:10px}
.copy{display:inline-flex;gap:10px;align-items:center;margin-top:12px}
input{width:100%;padding:12px;border-radius:10px;border:1px solid #222;background:#0c0c0c;color:#fff}
@media (max-width:480px){
  h1,h2{font-size:20px}
  a.button,button.button{min-width:120px;padding:11px 14px}
}
"""

def rate_limit_page(retry_after: int, body_preview: str, retry_link: str, index_link: str):
    return render_template_string(
        f"""<!doctype html><html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Rate limited</title>
<style>{MOBILE_CSS}</style>
</head><body><main>
<div class="card">
  <h2>Discord is rate limiting login</h2>
  <p>Please wait and try again. This is temporary and happens when too many requests hit Discord from the same IP.</p>
  <div class="meta">Retry-After: <strong>{retry_after or "unknown"}</strong> seconds</div>
  <pre>{body_preview}</pre>
  <div class="row">
    <a class="button" href="{retry_link}">Retry now</a>
    <a class="alt button" href="{index_link}">Return to site</a>
  </div>
</div>
</main></body></html>"""
    ), 429

def login_error_page(title: str, brief: str, body_preview: str, index_link: str):
    return render_template_string(
        f"""<!doctype html><html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title}</title>
<style>{MOBILE_CSS}</style>
</head><body><main>
<div class="card">
  <h2>{title}</h2>
  <p>Something went wrong during login.</p>
  <pre>{brief}</pre>
  <pre>{body_preview}</pre>
  <div class="row">
    <a class="alt button" href="{index_link}">Return to site</a>
  </div>
</div>
</main></body></html>"""
    ), 400

def id_gate_page(did: str, index_link: str):
    # Instead of showing the Copy ID page, just redirect back to your site
    return redirect(f"{index_link}?discord_id={did}", code=302)

# app.py — Part 5/6
@app.route("/login/discord")
def login_discord():
    state = make_state()
    redirect_uri = DISCORD_REDIRECT or f"{request.url_root.rstrip('/')}/login/discord/callback"
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        "&response_type=code&scope=identify"
        f"&state={state}"
    )
    return redirect(auth_url)

def _discord_callback():
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    if not state or not verify_state(state):
        return login_error_page("Invalid or expired state", "state invalid", "", IONOS_INDEX)
    if not code:
        return login_error_page("Missing OAuth code", "code missing", "", IONOS_INDEX)

    redirect_uri = DISCORD_REDIRECT or request.base_url
    token_resp = discord_exchange_token(code, redirect_uri)

    if isinstance(token_resp, dict) and token_resp.get("error") == "rate_limited":
        retry_after = token_resp.get("retry_after", None)
        body_preview = (token_resp.get("body") or "")[:800]
        retry_link = request.base_url + "?" + request.query_string.decode()
        return rate_limit_page(retry_after, body_preview, retry_link, IONOS_INDEX)

    if isinstance(token_resp, dict) and token_resp.get("error"):
        brief = json.dumps({k: token_resp.get(k) for k in ("error", "status") if k in token_resp})
        body_preview = (token_resp.get("body") or "")[:800]
        return login_error_page("Login failed", brief, body_preview, IONOS_INDEX)

    access_token = token_resp.get("access_token")
    if not access_token:
        return login_error_page("Login failed", "no access_token", json.dumps(token_resp)[:800], IONOS_INDEX)

    user_info = discord_get_user(access_token)
    if isinstance(user_info, dict) and user_info.get("error") == "rate_limited":
        retry_after = user_info.get("retry_after", None)
        body_preview = (user_info.get("body") or "")[:800]
        retry_link = request.base_url + "?" + request.query_string.decode()
        return rate_limit_page(retry_after, body_preview, retry_link, IONOS_INDEX)

    did = str(user_info.get("id") or "")
    if not did:
        return login_error_page("Discord user lookup failed", json.dumps(user_info)[:200], (user_info.get("body") or "")[:800], IONOS_INDEX)

    try:
        if global_override or bool(admin_overrides.get(did, False)):
            discord_add_role(did)
    except Exception:
        logging.exception("Role assignment failed")

    session.permanent = True
    session["user"] = {
        "id": did,
        "username": user_info.get("username", ""),
        "discriminator": user_info.get("discriminator", ""),
        "ts": now_ts()
    }
    login_history.append(session["user"])

    # ✅ Instead of showing the Copy ID page, redirect straight back to your site
    return redirect(f"{IONOS_INDEX}?discord_id={did}", code=302)
    
@app.route("/login/discord/callback")
def discord_callback_login():
    return _discord_callback()

@app.route("/discord/callback")
def discord_callback_plain():
    return _discord_callback()

# -----------------------------------------------------------------------------
# Session / Portal / Logout / Status / Health
# -----------------------------------------------------------------------------
@app.route("/portal/me")
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({"ok": True, "user": user}), 200

@app.route("/logout")
def logout():
    session.clear()
    return redirect(IONOS_INDEX)

@app.route("/status/<did>")
def status(did):
    # Global override
    if global_override:
        return jsonify({
            "ok": True,
            "member": True,
            "role_granted": True,
            "username": "GLOBAL_OVERRIDE",
            "message": "GLOBAL OVERRIDE ACTIVE"
        }), 200

    # Admin override
    if admin_overrides.get(did):
        return jsonify({
            "ok": True,
            "member": True,
            "role_granted": True,
            "username": "ADMIN_OVERRIDE",
            "message": "ADMIN OVERRIDE"
        }), 200

    # Normal member lookup
    member = discord_member(did)
    if "user" in member:
        username = member.get("user", {}).get("username", "")
        return jsonify({
            "ok": True,
            "member": True,
            "role_granted": True,  # ✅ always true now
            "username": username,
            "message": f"Welcome {username}! Don’t forget to get your key from the website."
        }), 200

    # Lookup failed
    return jsonify({
        "ok": False,
        "member": False,
        "role_granted": False,
        "message": f"Member lookup error (status {member.get('status_code')})"
    }), 404

@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": now_ts()}), 200

# app.py — Part 6/6
# -----------------------------------------------------------------------------
# Overrides (owner only)
# -----------------------------------------------------------------------------
@app.route("/override/all", methods=["GET", "POST", "DELETE"])
def override_all():
    global global_override
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    if request.method == "GET":
        return jsonify({"ok": True, "global_override": global_override}), 200
    if request.method == "POST":
        global_override = True
        save_state()
        return jsonify({"ok": True, "global_override": True}), 200
    if request.method == "DELETE":
        global_override = False
        save_state()
        return jsonify({"ok": True, "global_override": False}), 200
    return jsonify({"ok": False, "message": "Method not allowed"}), 405

@app.route("/override/<did>", methods=["GET", "POST", "DELETE"])
def override_user(did):
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    if request.method == "GET":
        return jsonify({"ok": True, "user_override": bool(admin_overrides.get(did)), "discord_id": did}), 200
    if request.method == "POST":
        admin_overrides[did] = {"username": "", "discriminator": ""}
        save_state()
        return jsonify({"ok": True, "user_override": True, "discord_id": did}), 200
    if request.method == "DELETE":
        admin_overrides.pop(did, None)
        save_state()
        return jsonify({"ok": True, "user_override": False, "discord_id": did}), 200
    return jsonify({"ok": False, "message": "Method not allowed"}), 405

# -----------------------------------------------------------------------------
# Role removal (owner only)
# -----------------------------------------------------------------------------
@app.route("/remove_role_now/<did>", methods=["POST"])
def remove_role_now(did):
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    success = discord_remove_role(did)
    return jsonify({"ok": success, "discord_id": did}), (200 if success else 500)

@app.route("/remove_role_all", methods=["POST"])
def remove_role_all():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN:
        return jsonify({"ok": False, "message": "Missing guild or bot token"}), 400
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "User-Agent": UA}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        return jsonify({"ok": False, "message": "Failed to fetch members", "status": resp.status_code}), 500
    members = resp.json()
    removed, failed = [], []
    for m in members:
        did = str(m["user"]["id"])
        r = requests.delete(
            f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}",
            headers=headers, timeout=15
        )
        (removed if r.status_code in (200, 204) else failed).append(did)
    return jsonify({
        "ok": True,
        "removed_count": len(removed),
        "failed_count": len(failed),
        "removed_sample": removed[:10],
        "failed_sample": failed[:10]
    }), 200

# -----------------------------------------------------------------------------
# Run server
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
