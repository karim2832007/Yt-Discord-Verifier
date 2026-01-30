import hashlib

class DeviceUtils:

    @staticmethod
    def fingerprint(raw: str) -> str:
        """Create a stable device fingerprint from any raw string."""
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def normalize(device_id: str) -> str:
        """Normalize device IDs to avoid duplicates."""
        return device_id.strip().lower()