from datetime import datetime
from app.models.nsfw import NSFWToken
from app.extensions import db

class NSFWService:

    @staticmethod
    def create_token(user_id: int, token: str, expires_at):
        # Convert ISO string → datetime
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)

        # Convert UNIX timestamp → datetime
        elif isinstance(expires_at, (int, float)):
            expires_at = datetime.utcfromtimestamp(expires_at)

        t = NSFWToken(
            user_id=user_id,
            token=token,
            expires_at=expires_at
        )

        db.session.add(t)
        db.session.commit()
        return t

    @staticmethod
    def get_token(token: str):
        return NSFWToken.query.filter_by(token=token).first()
