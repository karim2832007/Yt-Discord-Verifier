from app.models.user import User
from app.extensions import db

class UserService:

    @staticmethod
    def get_user_by_email(email: str):
        return User.query.filter_by(email=email).first()

    @staticmethod
    def get_user_by_id(user_id: int):
        return User.query.get(user_id)

    @staticmethod
    def create_user(email: str, username: str, password_hash: str):
        user = User(
            email=email,
            username=username,
            password_hash=password_hash
        )
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def update_user(user: User):
        db.session.commit()
        return user
