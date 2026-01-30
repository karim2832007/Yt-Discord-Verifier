from flask import Blueprint, jsonify
from flask import session


bp = Blueprint("admin", __name__)

@bp.get("/status")
def status():
    return jsonify({"admin": True})
