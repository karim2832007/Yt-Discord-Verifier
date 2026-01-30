from app.services.user_service import UserService
from app.services.discord_service import DiscordService

class DiscordSync:

    @staticmethod
    def sync_roles(user_id: int, roles: list[str]):
        user = UserService.get_user_by_id(user_id)
        if not user:
            return None

        # Convert list to comma-separated string
        roles_str = ",".join(roles)

        DiscordService.link_discord(
            user,
            discord_id=user.discord_id,
            username=user.discord_username,
            avatar=user.discord_avatar,
            roles=roles_str
        )

        return user

    @staticmethod
    def clear_roles(user_id: int):
        user = UserService.get_user_by_id(user_id)
        if not user:
            return None

        user.discord_roles = None
        UserService.update_user(user)
        return user