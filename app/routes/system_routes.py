from flask import Blueprint, send_from_directory
import os

bp = Blueprint("system", __name__)

@bp.route("/favicon.ico")
def favicon_ico():
    static_folder = os.path.join(os.path.dirname(__file__), "..", "static")
    return send_from_directory(static_folder, "favicon.svg")

@bp.route("/ping")
def ping():
    return {"system": "online"}