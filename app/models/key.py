from app.extensions import db
from datetime import datetime
import uuid

class Key(db.Model):
    __tablename__ = "keys"

    id = db.Column(db.String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    key_value = db.Column(db.String(64), unique=True, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    type = db.Column(db.String(32), default="premium")
    role_id = db.Column(db.String(64), nullable=True)

    status = db.Column(db.String(32), default="active")
    duration_minutes = db.Column(db.Integer, default=1440)

    created_at = db.Column(db.Float, default=lambda: datetime.utcnow().timestamp())
    expires_at = db.Column(db.Float, nullable=True)

    nsfw = db.Column(db.Boolean, default=False)
    perks = db.Column(db.String(256), nullable=True)
    max_devices = db.Column(db.Integer, default=1)

    user = db.relationship("User", back_populates="keys")

    devices = db.relationship(
        "Device",
        back_populates="key",
        cascade="all, delete-orphan"
    )

    def to_record(self):
        expiry_iso = None
        expired = False

        if self.expires_at:
            expiry_iso = datetime.utcfromtimestamp(self.expires_at).isoformat()
            expired = datetime.utcnow().timestamp() > self.expires_at

        return {
            "key_id": self.id,
            "key_value": self.key_value,
            "type": self.type,
            "role_id": self.role_id,
            "status": self.status,
            "expired": expired,
            "expires_at": self.expires_at,
            "expiry_iso": expiry_iso,
            "duration_minutes": self.duration_minutes,
            "created_at": self.created_at
        }