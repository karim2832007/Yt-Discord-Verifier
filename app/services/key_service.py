import uuid
from datetime import datetime
from app.extensions import db
from app.models.key import Key

class KeyService:

    @staticmethod
    def generate_key_string():
        return f"GM-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"

    @staticmethod
    def create_key(user_id="anonymous", duration_minutes=1440, type="premium", role_id=None):
        key_value = KeyService.generate_key_string()

        expires_at = datetime.utcnow().timestamp() + duration_minutes * 60

        key = Key(
            key_value=key_value,
            user_id=user_id,
            type=type,
            role_id=role_id,
            duration_minutes=duration_minutes,
            expires_at=expires_at
        )

        db.session.add(key)
        db.session.commit()
        return key
