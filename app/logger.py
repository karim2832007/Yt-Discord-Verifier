import logging
import json
from logging.handlers import RotatingFileHandler

from .config import Config


def make_logger(name: str = "yt_discord_verifier", logfile: str = "") -> logging.Logger:
    """
    Creates a JSON‑formatted logger with optional rotating file output.
    """
    logger = logging.getLogger(name)

    # Prevent duplicate handlers if create_app() is called multiple times
    if logger.handlers:
        return logger

    cfg = Config()
    logger.setLevel(logging.DEBUG if cfg.DEBUG else logging.INFO)

    # JSON log format
    fmt = json.dumps({
        "time": "%(asctime)s",
        "level": "%(levelname)s",
        "name": "%(name)s",
        "req_id": "%(req_id)s",
        "msg": "%(message)s"
    })

    formatter = logging.Formatter(fmt)

    # Console output
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    # Optional file logging
    if logfile:
        file_handler = RotatingFileHandler(logfile, maxBytes=10_000_000, backupCount=3)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger