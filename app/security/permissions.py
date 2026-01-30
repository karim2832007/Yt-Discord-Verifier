from app.services.user_service import UserService

class Permissions:

    @staticmethod
    def is_admin(user_id: int) -> bool:
        user = UserService.get_user_by_id(user_id)
        if not user:
            return False

        # Admins are identified by a Discord role
        if not user.discord_roles:
            return False

        roles = user.discord_roles.split(",")
        return "admin" in [r.lower() for r in roles]

    @staticmethod
    def has_role(user_id: int, role: str) -> bool:
        user = UserService.get_user_by_id(user_id)
        if not user or not user.discord_roles:
            return False

        roles = user.discord_roles.split(",")
        return role.lower() in [r.lower() for r in roles]