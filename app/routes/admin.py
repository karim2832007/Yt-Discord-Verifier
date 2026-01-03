from flask import Blueprint, request, jsonify, render_template

from ..exceptions import AuthorizationError
from ..stores import list_keys, list_override_audit

bp = Blueprint("admin", __name__)


# -----------------------------
# Helper: check admin
# -----------------------------
def _is_admin(app, user_id: str) -> bool:
    try:
        uid = int(str(user_id))
        return uid in app.cfg.ADMIN_USER_IDS
    except Exception:
        return False


# -----------------------------
# Admin: list all keys
# -----------------------------
@bp.route("/admin/keys", methods=["GET"])
def admin_list_keys():
    from flask import current_app as app

    user_id = request.headers.get("X-User-Id")
    if not _is_admin(app, user_id):
        raise AuthorizationError("not admin")

    return jsonify({"ok": True, "keys": list_keys()}), 200


# -----------------------------
# Admin: list override audit log
# -----------------------------
@bp.route("/admin/overrides", methods=["GET"])
def admin_list_overrides():
    from flask import current_app as app

    user_id = request.headers.get("X-User-Id")
    if not _is_admin(app, user_id):
        raise AuthorizationError("not admin")

    return jsonify({"ok": True, "overrides": list_override_audit()}), 200


# -----------------------------
# Admin panel page
# -----------------------------
@bp.route("/admin")
def admin():
    # You can replace this with your own HTML later
    return "<h1>Admin Panel</h1><p>Replace with admin.html template.</p>"