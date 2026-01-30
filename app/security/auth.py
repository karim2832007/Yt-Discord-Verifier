import jwt
from datetime import datetime, timedelta
from passlib.hash import bcrypt

SECRET_KEY = "SUPER_SECRET_KEY_CHANGE_THIS"

class Auth:

    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hash(password)

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        return bcrypt.verify(password, hashed)

    @staticmethod
    def create_token(user_id: int) -> str:
        payload = {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(days=7)
        }
        return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    @staticmethod
    def verify_token(token: str):
        if not token:
            return None

        # Allow "Bearer <token>"
        if token.startswith("Bearer "):
            token = token.split(" ", 1)[1]

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return data.get("user_id")
        except Exception:
            return None