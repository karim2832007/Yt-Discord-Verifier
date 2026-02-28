import threading
from app import start_api
from bot import start_bot

# ⭐ Load discord_service so its events & functions register
import core.discord_service

if __name__ == "__main__":
    threading.Thread(target=start_api, daemon=True).start()
    start_bot()
