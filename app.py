# app.py (part 1/2)
import os
import time
import secrets
import hmac
import hashlib
import base64
import logging
from datetime import timedelta
import requests
from flask import Flask, redirect, request, session, jsonify, render_template_string
from dotenv import load_dotenv
from flask_cors import CORS
import json

# ---------------------------------------------------------------------------
# Load environment and configure app
# ---------------------------------------------------------------------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=1)

# Cookie config - adjust SESSION_COOKIE_DOMAIN if you deploy under a different domain
SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", ".gaming-mods.com")
app.config.update(
    SESSION_COOKIE_DOMAIN=SESSION_COOKIE_DOMAIN,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
)

IONOS_BASE = os.environ.get("BASE_URL", "https://gaming-mods.com").rstrip("/")
IONOS_INDEX = f"{IONOS_BASE}/index.html"
IONOS_ADMIN = f"{IONOS_BASE}/admin.html"
IONOS_GAMES = f"{IONOS_BASE}/games.html"
IONOS_DONATE = f"{IONOS_BASE}/donate.html"
IONOS_PRIVACY = f"{IONOS_BASE}/privacy.html"

CORS(app, origins=[IONOS_BASE], supports_credentials=True)

# ---------------------------------------------------------------------------
# Discord & Owner settings (required env vars)
# ---------------------------------------------------------------------------
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
OWNER_ID = os.environ.get("OWNER_ID", "1329817290052734980")
DISCORD_REDIRECT = os.environ.get("DISCORD_REDIRECT", "").strip()

# ---------------------------------------------------------------------------
# State persistence & overrides
# ---------------------------------------------------------------------------
global_override = False
admin_overrides = {}
login_history = []
STATE_FILE = "override_state.json"


def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({
                "global_override": global_override,
                "admin_overrides": admin_overrides
            }, f)
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
STATE_TTL = 15 * 60
logging.basicConfig(level=logging.INFO)
app.config["PROPAGATE_EXCEPTIONS"] = True


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
    return bool(user and str(user.get("id")) == str(OWNER_ID))


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {}
# app.py (part 2/2-A)
# ---------------------------------------------------------------------------
# Discord API helpers
# ---------------------------------------------------------------------------
def discord_exchange_token(code: str, redirect_uri: str) -> dict:
    """
    Exchange OAuth code for tokens with safe, non-blocking behaviour for long Retry-After.
    Returns payload on success (contains access_token) or structured error dict on failure.
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
        "User-Agent": "GamingMods-Verifier/1.0 (+https://gaming-mods.com)"
    }

    MAX_ATTEMPTS = 4
    BACKOFF_BASE = 0.5
    MAX_IN_REQUEST_SLEEP = 5  # seconds

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = requests.post(url, data=data, headers=headers, timeout=15)
        except requests.RequestException as exc:
            logging.warning("discord_exchange_token network error (attempt %d): %s", attempt, exc)
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
            logging.warning("discord_exchange_token received 429 (attempt %d). Retry-After: %s", attempt, retry_after)

            if retry_after and retry_after > MAX_IN_REQUEST_SLEEP:
                return {
                    "error": "rate_limited",
                    "status": 429,
                    "retry_after": retry_after,
                    "body": resp.text,
                    "json": _safe_json(resp)
                }

            sleep_for = retry_after if (retry_after and retry_after > 0) else (BACKOFF_BASE * (2 ** (attempt - 1)))
            sleep_for = min(sleep_for, MAX_IN_REQUEST_SLEEP)
            if attempt == MAX_ATTEMPTS:
                return {"error": "token_exchange_failed", "status": 429, "body": resp.text, "json": _safe_json(resp)}
            time.sleep(sleep_for)
            continue

        if 500 <= resp.status_code < 600:
            logging.warning("discord_exchange_token server error %s (attempt %d)", resp.status_code, attempt)
            if attempt == MAX_ATTEMPTS:
                return {"error": "token_exchange_failed", "status": resp.status_code, "body": resp.text, "json": _safe_json(resp)}
            time.sleep(min(BACKOFF_BASE * (2 ** (attempt - 1)), MAX_IN_REQUEST_SLEEP))
            continue

        try:
            payload = resp.json()
        except Exception:
            payload = {}
        if resp.status_code != 200:
            logging.warning("discord_exchange_token bad status %s: %s", resp.status_code, resp.text)
            return {"error": "token_exchange_failed", "status": resp.status_code, "body": resp.text, "json": payload}

        return payload

    return {"error": "token_exchange_failed", "status": "max_retries_exceeded"}


def discord_get_user(token: str) -> dict:
    try:
        resp = requests.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "GamingMods-Verifier/1.0 (+https://gaming-mods.com)"},
            timeout=15
        )
    except Exception as e:
        return {"error": "user_fetch_failed", "message": str(e)}
    try:
        data = resp.json()
    except Exception:
        data = {}
    if resp.status_code != 200:
        return {"error": "user_fetch_failed", "status": resp.status_code, "body": resp.text, "json": data}
    return data


def discord_member(did: str) -> dict:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN:
        return {"status_code": 400, "error": "missing_guild_or_bot_token"}
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}"
    resp = requests.get(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
    if resp.status_code == 200:
        try:
            return resp.json()
        except Exception:
            return {"status_code": resp.status_code, "error": resp.text}
    return {"status_code": resp.status_code, "error": resp.text}


def discord_has_role(member: dict) -> bool:
    return str(DISCORD_ROLE_ID) in [str(r) for r in member.get("roles", [])]


def discord_add_role(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN or not DISCORD_ROLE_ID:
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    resp = requests.put(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
    return resp.status_code in (200, 204)


def discord_remove_role(did: str) -> bool:
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN or not DISCORD_ROLE_ID:
        return False
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{did}/roles/{DISCORD_ROLE_ID}"
    resp = requests.delete(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
    return resp.status_code in (200, 204)


def should_assign_on_login(did: str) -> bool:
    return global_override or bool(admin_overrides.get(did, False))


# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_exception(e):
    logging.exception("Unhandled exception:")
    return jsonify({"ok": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# Front-end redirects
# ---------------------------------------------------------------------------
@app.route("/")
def serve_index():
    return redirect(IONOS_BASE)


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

# app.py (part 2/2-B)
# ---------------------------------------------------------------------------
# OAuth endpoints
# ---------------------------------------------------------------------------
@app.route("/login/discord")
def login_discord():
    state = make_state()
    redirect_uri = DISCORD_REDIRECT or f"{request.url_root.rstrip('/')}/login/discord/callback"
    auth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code&scope=identify"
        f"&state={state}"
    )
    return redirect(auth_url)


def _discord_callback():
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    if not state or not verify_state(state):
        return "Invalid or expired state", 400
    if not code:
        return "Missing code", 400

    redirect_uri = DISCORD_REDIRECT or request.base_url
    token_resp = discord_exchange_token(code, redirect_uri)

    # If rate-limited with long Retry-After, show friendly retry page without blocking worker
    if isinstance(token_resp, dict) and token_resp.get("error") == "rate_limited":
        retry_after = token_resp.get("retry_after", None)
        body_preview = (token_resp.get("body") or "")[:1000]
        return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Discord rate limited</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <style>
    body{background:#0b0b0b;color:#eee;font-family:Inter,SegoeUI,Arial;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
    .card{max-width:720px;padding:28px;border-radius:12px;background:linear-gradient(180deg,#0f0f0f,#070707);box-shadow:0 20px 50px rgba(0,0,0,0.7);text-align:center}
    h1{color:#f0c851;margin:0 0 8px;font-size:20px}
    p{color:#ccc;margin:8px 0 12px}
    .meta{font-family:monospace;color:#bbb;background:#080808;padding:10px;border-radius:8px;text-align:left;max-height:160px;overflow:auto}
    .actions{margin-top:14px}
    a.button{display:inline-block;padding:10px 14px;border-radius:10px;background:#d4af37;color:#070707;font-weight:700;text-decoration:none;margin:0 6px}
    a.link{color:#9fb8ff;text-decoration:underline}
  </style>
</head>
<body>
  <div class="card">
    <h1>Discord is rate limiting token exchanges</h1>
    <p>We received a rate-limit response from Discord. Please wait and try again. If the problem persists, try again later.</p>
    <div class="meta"><strong>Retry-After:</strong> {{ retry_after }} seconds
    <br/><br/><strong>Server response (truncated):</strong>
    <pre>{{ body_preview }}</pre></div>
    <div class="actions">
      <a class="button" href="{{ retry_link }}">Retry now</a>
      <a class="link" href="{{ index_link }}">Return to site (without logging in)</a>
    </div>
  </div>
</body>
</html>
        """, retry_after=retry_after, body_preview=body_preview, retry_link=request.base_url + "?" + request.query_string.decode(), index_link=IONOS_INDEX), 429

    if isinstance(token_resp, dict) and token_resp.get("error"):
        logging.warning("Token exchange failed: %s", token_resp)
        brief = json.dumps({k: token_resp.get(k) for k in ("error", "status") if k in token_resp})
        body_preview = (token_resp.get("body") or "")[:800]
        return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"/><title>Login error</title><meta name="viewport"content="width=device-width,initial-scale=1"/></head>
<body style="background:#070707;color:#eee;font-family:Inter,SegoeUI,Arial;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
  <div style="max-width:720px;padding:24px;border-radius:10px;background:#0c0c0c">
    <h2 style="color:#f0c851;margin:0 0 8px">Login failed</h2>
    <p style="color:#ccc">Token exchange failed. Details:</p>
    <pre style="background:#080808;color:#ddd;padding:10px;border-radius:8px;overflow:auto">{{ brief }}</pre>
    <pre style="background:#020202;color:#ddd;padding:10px;border-radius:8px;overflow:auto">{{ body_preview }}</pre>
    <p style="margin-top:12px"><a style="color:#d4af37" href="{{ index_link }}">Return to site</a></p>
  </div>
</body>
</html>
        """, brief=brief, body_preview=body_preview, index_link=IONOS_INDEX), 400

    access_token = token_resp.get("access_token")
    if not access_token:
        logging.warning("Token response missing access_token: %s", token_resp)
        return jsonify({"ok": False, "message": "Token exchange succeeded but no access_token returned", "details": token_resp}), 400

    user_info = discord_get_user(access_token)
    did = str(user_info.get("id", "") or "")
    if not did:
        logging.warning("discord_get_user failed: %s", user_info)
        return jsonify({"ok": False, "message": "Discord user lookup failed", "details": user_info}), 400

    try:
        if should_assign_on_login(did):
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

    # ID copy gate page then send to front-end index with discord_id query param
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Confirm Your Discord ID</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{background:#0a0a0a;color:#eee;font-family:Inter,SegoeUI,Arial, sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
    .card{background:rgba(0,0,0,0.6);padding:2rem;border-radius:12px;box-shadow:0 0 20px rgba(0,0,0,0.7);text-align:center;max-width:520px}
    h2{color:#FFD700;margin-bottom:.5rem}
    p{color:#ccc}
    .id{font-size:1.2rem;margin:1rem 0;color:#fff;word-break:break-all}
    .row{display:flex;gap:.75rem;justify-content:center;margin-top:1rem}
    button{padding:.75rem 1.25rem;border:none;border-radius:8px;cursor:pointer;font-weight:bold;color:#fff;background:#111}
    button.primary{background:#2b2b2b}
    button.enabled{background:#1a73e8}
    button.disabled{opacity:.6;cursor:not-allowed}
  </style>
</head>
<body>
  <div class="card">
    <h2>Login successful.</h2>
    <p class="id">Your Discord ID: <strong id="did">{{ did }}</strong></p>
    <div class="row">
      <button id="copy" class="primary">Copy ID</button>
      <button id="continue" class="disabled" disabled>Continue</button>
    </div>
  </div>

  <script>
    const didEl = document.getElementById('did');
    const copyBtn = document.getElementById('copy');
    const contBtn = document.getElementById('continue');
    const DID = didEl.textContent.trim();
    const TARGET = "{{ ionos_index }}";

    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(DID);
        copyBtn.textContent = 'Copied!';
        contBtn.disabled = false;
        contBtn.classList.remove('disabled');
        contBtn.classList.add('enabled');
      } catch (err) {
        const range = document.createRange();
        range.selectNodeContents(didEl);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        copyBtn.textContent = 'Select and press Ctrl+C';
      }
    });

    contBtn.addEventListener('click', () => {
      if (contBtn.disabled) return;
      const sep = TARGET.includes('?') ? '&' : '?';
      window.location.href = TARGET + sep + 'discord_id=' + encodeURIComponent(DID);
    });
  </script>
</body>
</html>
    """, did=did, ionos_index=IONOS_INDEX)


@app.route("/login/discord/callback")
def discord_callback_login():
    return _discord_callback()


@app.route("/discord/callback")
def discord_callback_plain():
    return _discord_callback()


# ---------------------------------------------------------------------------
# Session / Portal / Logout / Status
# ---------------------------------------------------------------------------
@app.route("/portal/me")
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({"ok": True, "user": user}), 200


@app.route("/logout")
def logout():
    session.clear()
    return redirect(IONOS_BASE)


@app.route("/status/<did>")
def status(did):
    if global_override:
        return jsonify({"ok": True, "role_granted": True, "message": "GLOBAL OVERRIDE ACTIVE"}), 200
    if admin_overrides.get(did):
        return jsonify({"ok": True, "role_granted": True, "message": "ADMIN OVERRIDE"}), 200
    member = discord_member(did)
    if "roles" in member:
        has = discord_has_role(member)
        return jsonify({"ok": True, "role_granted": has, "message": ("Role present" if has else "Role missing")}), 200
    return jsonify({"ok": False, "role_granted": False, "message": f"Member lookup error (status {member.get('status_code')})"}), 404


@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": now_ts()}), 200


# ---------------------------------------------------------------------------
# Override endpoints (owner only)
# ---------------------------------------------------------------------------
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


@app.route("/override", methods=["GET"])
def list_overrides():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    users = []
    for did, info in admin_overrides.items():
        users.append({"id": did, "username": info.get("username", ""), "discriminator": info.get("discriminator", "")})
    return jsonify({"ok": True, "global_override": global_override, "users": users}), 200


# ---------------------------------------------------------------------------
# Role removal endpoints (owner only)
# ---------------------------------------------------------------------------
@app.route("/remove_role_now/<did>", methods=["POST"])
def remove_role_now(did):
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    success = discord_remove_role(did)
    status_code = 200 if success else 500
    return jsonify({"ok": success, "discord_id": did}), status_code


@app.route("/remove_role_all", methods=["POST"])
def remove_role_all():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    if not DISCORD_GUILD_ID or not DISCORD_BOT_TOKEN:
        return jsonify({"ok": False, "message": "Missing guild or bot token"}), 400
    url = f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members?limit=1000"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
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
        if r.status_code in (200, 204):
            removed.append(did)
        else:
            failed.append(did)
    return jsonify({
        "ok": True,
        "removed_count": len(removed),
        "failed_count": len(failed),
        "removed_sample": removed[:10],
        "failed_sample": failed[:10]
    }), 200


# ---------------------------------------------------------------------------
# Run server
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)