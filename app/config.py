import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret")
    DEBUG = True

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///database.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JSON_AS_ASCII = False

    # ⭐ EXACT SAME SESSION SETTINGS AS OLD SITE
    SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "gamingmods_session")
    SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", ".gaming-mods.com")
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "None")
    SESSION_COOKIE_SECURE = str(os.environ.get("SESSION_COOKIE_SECURE", "1")).lower() in ("1", "true", "yes")
    SESSION_COOKIE_HTTPONLY = True
