from app.extensions import db

from .user import User
from .device import Device
from .key import Key
from .perks import Perk
from .nsfw import NSFWToken
from .admin import AdminLog
from .game import Game
from .game_download_link import GameDownloadLink  # NEW

__all__ = [
    "User",
    "Device",
    "Key",
    "Perk",
    "NSFWToken",
    "AdminLog",
    "Game",
    "GameDownloadLink",  # NEW
]
