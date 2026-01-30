from app.models.game import Game
from app.extensions import db

class GameService:

    @staticmethod
    def get_all_games():
        return Game.query.all()

    @staticmethod
    def get_game_by_id(game_id: int):
        return Game.query.get(game_id)

    @staticmethod
    def add_game(title: str, description: str, iframe_url: str, download_url: str, tags: str):
        game = Game(
            title=title,
            description=description,
            iframe_url=iframe_url,
            download_url=download_url,
            tags=tags
        )
        db.session.add(game)
        db.session.commit()
        return game
