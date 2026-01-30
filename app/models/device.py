from app.extensions import db
from datetime import datetime

class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String, index=True, nullable=False)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    key_id = db.Column(db.String(64), db.ForeignKey("keys.id"))

    user = db.relationship("User", back_populates="devices")
    key = db.relationship("Key", back_populates="devices")