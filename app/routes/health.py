from flask import Blueprint, jsonify

bp = Blueprint("health", __name__)

@bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@bp.route("/", methods=["GET"])
def root():
    return jsonify({"message": "YT Discord Verifier API is running"}), 200