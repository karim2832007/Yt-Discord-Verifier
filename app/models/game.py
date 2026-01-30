from app.extensions import db
from datetime import datetime
from sqlalchemy.dialects.sqlite import JSON

class Game(db.Model):
    __tablename__ = "games"

    id = db.Column(db.Integer, primary_key=True)

    # Basic info
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=True)

    # Thumbnail image for the gallery
    image_url = db.Column(db.String, nullable=True)

    # Game version (optional)
    version = db.Column(db.String, nullable=True)

    # If true → show version badge instead of NEW badge
    is_versioned = db.Column(db.Boolean, default=False)

    # Iframe for playing in browser
    iframe_url = db.Column(db.String, nullable=True)

    # Legacy single download URL (optional)
    download_url = db.Column(db.String, nullable=True)

    # Tags stored as JSON array: ["action", "rpg", "fun"]
    tags = db.Column(JSON, nullable=True)

    # Cheat log stored as JSON list of objects
    # [
    #   { "title": "...", "effect": "...", "notes": "..." },
    #   ...
    # ]
    cheat_log = db.Column(JSON, nullable=True)

    # For NEW badge (7 days)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship: multiple download links
    download_links = db.relationship(
        "GameDownloadLink",
        backref="game",
        cascade="all, delete-orphan"
    )


