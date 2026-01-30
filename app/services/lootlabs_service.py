import requests
from app.utils.logger import Logger
from app.utils.env import env

class LootLabsService:
    BASE_URL = "https://api.lootlabs.gg/v1"
    TIMEOUT = 10

    API_KEY = env("LOOTLABS_API_KEY")

    @staticmethod
    def headers():
        return {
            "Authorization": f"Bearer {LootLabsService.API_KEY}",
            "Content-Type": "application/json"
        }

    @staticmethod
    def validate_key(key: str):
        url = f"{LootLabsService.BASE_URL}/keys/{key}/validate"
        try:
            r = requests.get(url, headers=LootLabsService.headers(), timeout=LootLabsService.TIMEOUT)
        except Exception as e:
            Logger.error("LootLabs validate error:", e)
            return {"success": False, "error": "connection_failed"}

        if r.status_code != 200:
            return {"success": False, "error": "invalid_key"}

        return {"success": True, "data": r.json()}

    @staticmethod
    def redeem_key(key: str):
        url = f"{LootLabsService.BASE_URL}/keys/{key}/redeem"
        try:
            r = requests.post(url, headers=LootLabsService.headers(), timeout=LootLabsService.TIMEOUT)
        except Exception as e:
            Logger.error("LootLabs redeem error:", e)
            return {"success": False, "error": "connection_failed"}

        if r.status_code != 200:
            return {"success": False, "error": "redeem_failed"}

        return {"success": True, "data": r.json()}

    @staticmethod
    def generate_redirect(redirect_url: str, click_id: str):
        return (
            f"https://lootlabs.gg/redirect?"
            f"api_key={LootLabsService.API_KEY}"
            f"&redirect_url={redirect_url}"
            f"&click_id={click_id}"
        )

    @staticmethod
    def verify_postback(data: dict):
        required = ["click_id"]
        for r in required:
            if r not in data:
                return {"success": False, "error": "missing_fields"}

        return {"success": True, "data": data}
