from datetime import datetime, timedelta

class TimeUtils:

    @staticmethod
    def now():
        return datetime.utcnow()

    @staticmethod
    def add_minutes(minutes: int):
        return datetime.utcnow() + timedelta(minutes=minutes)

    @staticmethod
    def add_hours(hours: int):
        return datetime.utcnow() + timedelta(hours=hours)

    @staticmethod
    def add_days(days: int):
        return datetime.utcnow() + timedelta(days=days)

    @staticmethod
    def expired(expiry_time: datetime) -> bool:
        return datetime.utcnow() > expiry_time