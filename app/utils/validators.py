class Validators:

    @staticmethod
    def require(data: dict, fields: list[str]):
        missing = [f for f in fields if f not in data or data[f] in (None, "")]
        return missing if missing else None

    @staticmethod
    def is_email(value: str):
        return "@" in value and "." in value

    @staticmethod
    def min_length(value: str, length: int):
        return len(value) >= length

    @staticmethod
    def max_length(value: str, length: int):
        return len(value) <= length