from app.models.user import User
from app.extensions import db

class DiscordService:

    @staticmethod
    def link_discord(user: User, discord_id: str, username: str, avatar: str, roles: str):
        user.discord_id = discord_id
        user.discord_username = username
        user.discord_avatar = avatar
        user.discord_roles = roles

        db.session.commit()
        return user

    @staticmethod
    def unlink_discord(user: User):
        user.discord_id = None
        user.discord_username = None
        user.discord_avatar = None
        user.discord_roles = None

        db.session.commit()
        return user
