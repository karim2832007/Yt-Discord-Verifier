from app.models.perks import Perk
from app.extensions import db

class PerksService:

    @staticmethod
    def add_perk(user_id: int, perk_type: str, value: str):
        perk = Perk(
            user_id=user_id,
            perk_type=perk_type,
            value=value
        )
        db.session.add(perk)
        db.session.commit()
        return perk

    @staticmethod
    def get_perks_for_user(user_id: int):
        return Perk.query.filter_by(user_id=user_id).all()
