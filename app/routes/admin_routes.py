from flask import Blueprint, jsonify

bp = Blueprint("admin", __name__)

@bp.get("/status")
def status():
    return jsonify({"admin": True})