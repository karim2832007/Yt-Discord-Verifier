import secrets
from datetime import datetime, timedelta

class TokenGenerator:

    @staticmethod
    def generate(length: int = 32) -> str:
        return secrets.token_hex(length)

    @staticmethod
    def generate_expiring(hours: int = 24):
        token = secrets.token_hex(32)
        expires_at = datetime.utcnow() + timedelta(hours=hours)
        return token, expires_at

    @staticmethod
    def generate_nsfw_token():
        token = secrets.token_hex(16)
        expires_at = datetime.utcnow() + timedelta(days=30)
        return token, expires_at