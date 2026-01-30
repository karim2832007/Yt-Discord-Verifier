import os
from dotenv import load_dotenv

load_dotenv()

def env(key: str, default=None):
    return os.getenv(key, default)