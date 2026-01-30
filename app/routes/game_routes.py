from flask import Blueprint, jsonify
from app.services.game_service import GameService
from flask import session

bp = Blueprint("games", __name__)

@bp.get("/")
def list_games():
    games = GameService.get_all_games()
    return jsonify([
        {
            "id": g.id,
            "title": g.title,
            "description": g.description,
            "iframe_url": g.iframe_url,
            "download_url": g.download_url,
            "tags": g.tags
        }
        for g in games
    ])
