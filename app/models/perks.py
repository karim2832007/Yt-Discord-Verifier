from app.extensions import db
from datetime import datetime

class Perk(db.Model):
    __tablename__ = "perks"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    perk_type = db.Column(db.String, nullable=False)  # VIP / Booster / Premium / Staff
    value = db.Column(db.String, nullable=True)       # JSON string

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="perks")