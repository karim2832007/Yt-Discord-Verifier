import os

class Config:
    def __init__(self):
        # Environment
        self.ENV = os.getenv("FLASK_ENV", "production")
        self.DEBUG = os.getenv("FLASK_DEBUG", "0") in ("1", "true", "True")

        # Security
        self.SECRET_KEY = os.getenv("SECRET_KEY", "change-me")

        # Discord OAuth (MATCHES oauth.py)
        self.DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
        self.DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
        self.DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT", "/login/discord/callback")
        self.DISCORD_API_BASE = os.getenv("DISCORD_API_BASE", "https://discord.com/api")

        # Admins
        self.ADMIN_USER_IDS = self._parse_int_list(os.getenv("ADMIN_USER_IDS", ""))

        # Feature flags
        self.ALLOW_CUSTOM_KEY = os.getenv("ALLOW_CUSTOM_KEY", "1") in ("1", "true", "True")

        # Logging
        self.LOG_FILE = os.getenv("LOG_FILE", "")
        self.GUNICORN_WORKERS = int(os.getenv("GUNICORN_WORKERS", "2"))

        # Session cookies
        self.SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "gamingmods_session")
        self.SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
        self.SESSION_COOKIE_SECURE = str(os.getenv("SESSION_COOKIE_SECURE", "1")).lower() in ("1", "true", "yes")
        self.SESSION_COOKIE_DOMAIN = os.getenv("SESSION_COOKIE_DOMAIN", ".gaming-mods.com")
        self.SESSION_COOKIE_HTTPONLY = True

    @staticmethod
    def _parse_int_list(raw: str):
        if not raw:
            return []
        return [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
