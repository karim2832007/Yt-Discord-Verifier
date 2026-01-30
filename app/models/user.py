from app.extensions import db
from datetime import datetime

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, index=True)

    # Login
    email = db.Column(db.String, unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Discord
    discord_id = db.Column(db.String, unique=True, nullable=True)
    discord_username = db.Column(db.String, nullable=True)
    discord_avatar = db.Column(db.String, nullable=True)
    discord_roles = db.Column(db.String, nullable=True)  # JSON string

    # NSFW
    nsfw_verified = db.Column(db.Boolean, default=False)
    nsfw_verified_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    keys = db.relationship("Key", back_populates="user")
    devices = db.relationship("Device", back_populates="user")
    perks = db.relationship("Perk", back_populates="user")
    nsfw_tokens = db.relationship("NSFWToken", back_populates="user")