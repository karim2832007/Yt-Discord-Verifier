#!/usr/bin/env python3
# app.py — Yt-Discord-Verifier (remade, fully fixed)
# - Assigns role at login
# - Generates keys with random length 10–18 (lowercase letters + digits)
# - Atomic key validation/consumption
# - Clean structure, no invalid dividers

import os
import time
import secrets
import hmac
import hashlib
import base64
import logging
import sqlite3
from datetime import timedelta
from urllib.parse import unquote
from dotenv import load_dotenv
from flask import Flask, redirect, request, session, jsonify, render_template_string, g
from flask_cors import CORS
import requests
import json

# -------------------------
# Environment / config
# -------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=1)

# Frontend origin (for CORS)
BASE_URL = os.environ.get("BASE_URL", "https://gaming-mods.com").rstrip("/")
CORS(app, origins=[BASE_URL], supports_credentials=True)

# Cookie settings (adjust domain as needed)
SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", ".gaming-mods.com")
app.config.update(
    SESSION_COOKIE_DOMAIN=SESSION_COOKIE_DOMAIN,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
)

# Discord & owner
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_ROLE_ID = os.environ.get("DISCORD_ROLE_ID", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
OWNER_ID = os.environ.get("OWNER_ID", "")

# Key generation config: random part length 10..18
KEY_DB_PATH = os.environ.get("KEY_DB_PATH", "issued_keys.sqlite3")
KEY_PREFIX = os.environ.get("KEY_PREFIX", "GMD")
MIN_RANDOM_LEN = int(os.environ.get("MIN_RANDOM_LEN", 10))
MAX_RANDOM_LEN = int(os.environ.get("MAX_RANDOM_LEN", 18))
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

# Logging
logging.basicConfig(level=logging.INFO)
app.config["PROPAGATE_EXCEPTIONS"] = True

# -------------------------
# Runtime state
# -------------------------
global_override = False
admin_overrides = {}
login_history = []
STATE_FILE = "override_state.json"


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

# -------------------------
# Helpers
# -------------------------
STATE_TTL = 15 * 60


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

# -------------------------
# SQLite key storage
# -------------------------
def get_key_db():
    db = getattr(g, "_key_db", None)
    if db is None:
        db = sqlite3.connect(KEY_DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
        g._key_db = db
    return db


@app.teardown_appcontext
def close_key_db(exception):
    db = getattr(g, "_key_db", None)
    if db is not None:
        db.close()


def ensure_key_table():
    db = get_key_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS issued_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT NOT NULL,
            key_text TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            consumed_at INTEGER
        );
        """
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_issued_keys_discord ON issued_keys(discord_id)")
    db.commit()


def _random_token():
    length = secrets.choice(range(MIN_RANDOM_LEN, MAX_RANDOM_LEN + 1))
    return ''.join(secrets.choice(ALPHABET) for _ in range(length))


def _build_key(discord_id: str, random_part: str) -> str:
    if KEY_PREFIX:
        return f"{KEY_PREFIX}-{discord_id}-{random_part}"
    return random_part


def create_unique_key(discord_id: str, max_attempts: int = 12) -> str:
    ensure_key_table()
    db = get_key_db()
    for _ in range(max_attempts):
        rp = _random_token()
        key_text = _build_key(discord_id, rp)
        try:
            db.execute(
                "INSERT INTO issued_keys (discord_id, key_text, created_at, consumed) VALUES (?, ?, ?, 0)",
                (str(discord_id), key_text, now_ts()),
            )
            db.commit()
            return key_text
        except sqlite3.IntegrityError:
            continue
    raise RuntimeError("Failed to generate unique key after multiple attempts")

# -------------------------
# Discord helpers
# -------------------------
def discord_exchange_token(code: str, redirect_uri: str) -> dict:
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
        "User-Agent": "GamingMods-Verifier/1.0 (+https://gaming-mods.com)",
    }
    try:
        resp = requests.post(url, data=data, headers=headers, timeout=15)
    except requests.RequestException as exc:
        logging.warning("discord_exchange_token network error: %s", exc)
        return {"error": "network_error", "message": str(exc)}
    if resp.status_code != 200:
        return {"error": "token_exchange_failed", "status": resp.status_code, "body": resp.text, "json": _safe_json(resp)}
    return _safe_json(resp)


def discord_get_user(token: str) -> dict:
    try:
        resp = requests.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "GamingMods-Verifier/1.0"},
            timeout=15,
        )
    except Exception as e:
        return {"error": "user_fetch_failed", "message": str(e)}
    if resp.status_code != 200:
        return {"status_code": resp.status_code, "error": resp.text}
    return _safe_json(resp)


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

# -------------------------
# Error handler
# -------------------------
@app.errorhandler(Exception)
def handle_exception(e):
    logging.exception("Unhandled exception:")
    return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Front-end redirects
# -------------------------
@app.route("/")
def index_redirect():
    return redirect(BASE_URL)


@app.route("/admin")
def serve_admin():
    if not require_owner():
        return "Forbidden", 403
    return redirect(f"{BASE_URL}/admin.html")


@app.route("/games")
def serve_games():
    return redirect(f"{BASE_URL}/games.html")


@app.route("/privacy")
def serve_privacy():
    return redirect(f"{BASE_URL}/privacy.html")


@app.route("/donate")
def serve_donate():
    return redirect(f"{BASE_URL}/donate.html")


@app.route("/admin/logins")
def admin_logins():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    return jsonify({"ok": True, "logins": login_history}), 200

# -------------------------
# OAuth endpoints (login and callback)
# -------------------------
@app.route("/login/discord")
def login_discord():
    state = make_state()
    redirect_uri = os.environ.get("DISCORD_REDIRECT") or f"{request.url_root.rstrip('/')}/login/discord/callback"
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
        return "Invalid or expired state", 400
    if not code:
        return "Missing code", 400

    redirect_uri = os.environ.get("DISCORD_REDIRECT") or request.base_url
    token_resp = discord_exchange_token(code, redirect_uri)
    if isinstance(token_resp, dict) and token_resp.get("error"):
        logging.warning("Token exchange failed: %s", token_resp)
        brief = json.dumps({k: token_resp.get(k) for k in ("error", "status") if k in token_resp})
        body_preview = (token_resp.get("body") or "")[:800]
        return render_template_string(
            "<html><body><h2>Login failed</h2><pre>{{ brief }}</pre><pre>{{ body_preview }}</pre></body></html>",
            brief=brief,
            body_preview=body_preview,
        ), 400

    access_token = token_resp.get("access_token")
    if not access_token:
        return jsonify({"ok": False, "message": "No access_token returned", "details": token_resp}), 400

    user_info = discord_get_user(access_token)
    did = str(user_info.get("id") or "")
    if not did:
        logging.warning("discord_get_user failed: %s", user_info)
        return jsonify({"ok": False, "message": "Discord user lookup failed", "details": user_info}), 400

    # Assign role at login (best effort)
    try:
        discord_add_role(did)
    except Exception:
        logging.exception("Role assignment attempt failed at login")

    session.permanent = True
    session["user"] = {"id": did, "username": user_info.get("username", ""), "discriminator": user_info.get("discriminator", ""), "ts": now_ts()}
    login_history.append(session["user"])

    return render_template_string(
        """
        <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Confirm Your Discord ID</title>
        <style>body{background:#0a0a0a;color:#eee;font-family:Inter,SegoeUI,Arial;height:100vh;display:flex;align-items:center;justify-content:center;margin:0}
        .card{background:rgba(0,0,0,0.6);padding:2rem;border-radius:12px;text-align:center;max-width:520px}
        h2{color:#FFD700;margin-bottom:.5rem} .id{font-size:1.2rem;margin:1rem 0;color:#fff;word-break:break-all}
        .row{display:flex;gap:.75rem;justify-content:center;margin-top:1rem} button{padding:.75rem 1.25rem;border:none;border-radius:8px;cursor:pointer;font-weight:bold;color:#fff;background:#111}
        button.primary{background:#2b2b2b} button.enabled{background:#1a73e8} button.disabled{opacity:.6;cursor:not-allowed}
        </style></head><body>
        <div class="card"><h2>Login successful.</h2>
        <p class="id">Your Discord ID: <strong id="did">{{ did }}</strong></p>
        <div class="row">
        <button id="copy" class="primary">Copy ID</button>
        <button id="continue" class="disabled" disabled>Continue</button>
        </div></div>
        <script>
        const didEl = document.getElementById('did');
        const copyBtn = document.getElementById('copy');
        const contBtn = document.getElementById('continue');
        const DID = didEl.textContent.trim();
        const TARGET = "{{ index }}";
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
        </script></body></html>
        """,
        did=did,
        index=BASE_URL + "/index.html",
    )


@app.route("/login/discord/callback")
def discord_callback_login():
    return _discord_callback()


@app.route("/discord/callback")
def discord_callback_plain():
    return _discord_callback()

# -------------------------
# Portal / session / status
# -------------------------
@app.route("/portal/me")
def portal_me():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    return jsonify({"ok": True, "user": user}), 200


@app.route("/logout")
def logout():
    session.clear()
    return redirect(BASE_URL)


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

# -------------------------
# Key endpoints
# -------------------------
@app.route("/generate_key", methods=["POST"])
def generate_key():
    user = session.get("user")
    if not user:
        return jsonify({"ok": False, "message": "Not logged in"}), 401
    discord_id = str(user.get("id"))
    try:
        body = request.get_json(silent=True) or {}
    except Exception:
        body = {}
    target_id = str(body.get("discord_id") or discord_id)
    if target_id != discord_id and not require_owner():
        return jsonify({"ok": False, "message": "Forbidden to generate for other IDs"}), 403
    try:
        key = create_unique_key(target_id)
        return jsonify({"ok": True, "key": key}), 200
    except Exception as e:
        logging.exception("Key generation failed")
        return jsonify({"ok": False, "message": "Key generation failed", "error": str(e)}), 500


@app.route("/validate_key/<path:did>/<path:key>", methods=["GET", "POST"])
def validate_key(did, key):
    try:
        did = unquote(did)
        key = unquote(key)
    except Exception:
        return jsonify({"ok": False, "message": "Bad encoding"}), 400

    if KEY_PREFIX:
        expected_prefix = f"{KEY_PREFIX}-{did}-"
        if not key.startswith(expected_prefix):
            return jsonify({"ok": False, "message": "Malformed key or mismatched discord id"}), 400

    ensure_key_table()
    db = get_key_db()
    row = db.execute("SELECT id, discord_id, consumed FROM issued_keys WHERE key_text = ?", (key,)).fetchone()
    if not row:
        return jsonify({"ok": False, "message": "Key not found"}), 404

    if str(row["discord_id"]) != str(did):
        return jsonify({"ok": False, "message": "Key does not belong to this ID"}), 400

    if int(row["consumed"]):
        return jsonify({"ok": False, "message": "Key already used"}), 410

    cur = db.execute(
        "UPDATE issued_keys SET consumed = 1, consumed_at = ? WHERE id = ? AND consumed = 0",
        (now_ts(), row["id"]),
    )
    db.commit()
    if cur.rowcount != 1:
        return jsonify({"ok": False, "message": "Key already used"}), 410

    return jsonify({"ok": True, "valid": True, "message": "Key valid and consumed"}), 200

# -------------------------
# Overrides (owner only)
# -------------------------
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
    return jsonify({"ok": True, "globaloverride": globaloverride, "users": users}), 200

-------------------------

Role remove helpers (owner only)

-------------------------
def discordremoverole(did: str) -> bool:
    if not DISCORDGUILDID or not DISCORDBOTTOKEN or not DISCORDROLEID:
        return False
    url = f"https://discord.com/api/guilds/{DISCORDGUILDID}/members/{did}/roles/{DISCORDROLEID}"
    resp = requests.delete(url, headers={"Authorization": f"Bot {DISCORDBOTTOKEN}"}, timeout=15)
    return resp.status_code in (200, 204)


@app.route("/removerolenow/<did>", methods=["POST"])
def removerolenow(did):
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    success = discordremoverole(did)
    status_code = 200 if success else 500
    return jsonify({"ok": success, "discordid": did}), statuscode


@app.route("/removeroleall", methods=["POST"])
def removeroleall():
    if not require_owner():
        return jsonify({"ok": False, "message": "Forbidden"}), 403
    if not DISCORDGUILDID or not DISCORDBOTTOKEN:
        return jsonify({"ok": False, "message": "Missing guild or bot token"}), 400
    url = f"https://discord.com/api/guilds/{DISCORDGUILDID}/members?limit=1000"
    headers = {"Authorization": f"Bot {DISCORDBOTTOKEN}"}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        return jsonify({"ok": False, "message": "Failed to fetch members", "status": resp.status_code}), 500
    members = safejson(resp)
    removed, failed = [], []
    for m in members:
        did = str(m["user"]["id"])
        r = requests.delete(f"https://discord.com/api/guilds/{DISCORDGUILDID}/members/{did}/roles/{DISCORDROLEID}", headers=headers, timeout=15)
        if r.status_code in (200, 204):
            removed.append(did)
        else:
            failed.append(did)
    return jsonify({"ok": True, "removedcount": len(removed), "failedcount": len(failed), "removedsample": removed[:10], "failedsample": failed[:10]}), 200

-------------------------

Run server

-------------------------
if name == "main":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)