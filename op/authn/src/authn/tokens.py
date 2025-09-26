# tokens.py
import secrets
import time
from typing import Tuple
from .settings import settings

def now() -> int:
    return int(time.time())

def new_session_id() -> str:
    # 32 bytes → ~43 char url-safe
    return secrets.token_urlsafe(32)

def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)

def session_expiries() -> Tuple[int, int]:
    """returns (expires_at, absolute_expires_at)"""
    n = now()
    return n + settings.SESSION_TTL_SECONDS, n + settings.SESSION_ABSOLUTE_SECONDS
