import time
import threading
import requests

from .exceptions import ValidationError


# ============================================================
# Duplicate‑exchange protection
# ============================================================

# Prevents multiple threads from exchanging the same code at once
_EXCHANGING_CODES = set()
_codes_lock = threading.RLock()

# Cache: prevents re‑exchanging the same code repeatedly
_CODE_RESULT_CACHE = {}
_CODE_CACHE_TTL = 120  # seconds


# ============================================================
# Cache Helpers
# ============================================================

def _cache_put(code, value):
    """Store a token exchange result with timestamp."""
    _CODE_RESULT_CACHE[code] = (value, time.time())


def _cache_get(code):
    """Return cached result if still valid."""
    item = _CODE_RESULT_CACHE.get(code)
    if not item:
        return None

    val, ts = item
    if time.time() - ts > _CODE_CACHE_TTL:
        _CODE_RESULT_CACHE.pop(code, None)
        return None

    return val


# ============================================================
# Token Exchange with Backoff
# ============================================================

def exchange_token_with_backoff(token_url, data, headers, logger=None):
    """
    Exchanges a Discord OAuth code for a token.
    Handles rate limits (429) gracefully.
    """

    try:
        resp = requests.post(token_url, data=data, headers=headers, timeout=8)
    except Exception as e:
        if logger:
            logger.error(f"Token exchange failed: {e}")
        raise ValidationError("Failed to contact Discord OAuth server")

    # Rate limited
    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        wait_s = int(retry_after) if retry_after and retry_after.isdigit() else 2

        if logger:
            logger.warning(f"Rate limited by Discord, retry_after={wait_s}")

        return {"error": "rate_limited", "retry_after": wait_s}

    # Other errors
    if resp.status_code >= 400:
        if logger:
            logger.warning(f"Discord token exchange failed: {resp.text}")
        raise ValidationError("Discord OAuth token exchange failed")

    return resp.json()


# ============================================================
# Safe Token Exchange (with dedupe + caching)
# ============================================================

def safe_token_exchange(token_url, data, headers, logger=None):
    """
    Prevents duplicate code exchanges, caches results,
    and handles rate limits cleanly.
    """

    code = data.get("code")
    if not code:
        raise ValidationError("Missing OAuth code")

    # 1. Check cache
    cached = _cache_get(code)
    if cached:
        if logger:
            logger.info("Using cached OAuth token result")
        return cached

    # 2. Prevent duplicate simultaneous exchanges
    with _codes_lock:
        if code in _EXCHANGING_CODES:
            raise ValidationError("OAuth code already being exchanged")

        _EXCHANGING_CODES.add(code)

    try:
        # 3. Perform exchange
        result = exchange_token_with_backoff(token_url, data, headers, logger)

        # 4. Cache result
        _cache_put(code, result)

        return result

    finally:
        # Always remove lock
        with _codes_lock:
            _EXCHANGING_CODES.discard(code)