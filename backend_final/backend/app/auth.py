"""
backend/app/auth.py

Lightweight authentication for the dashboard: a single configurable
analyst account (env-overridable) issuing short-lived JWTs. This is
deliberately simple — enough to keep the API off the open internet
without a full user-management system. For multi-analyst / role-based
access, swap `verify_credentials` for a real user table + password
hashes per row, and add a `role` claim to the token.
"""

import os
import hashlib
import hmac
import time
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SECRET_KEY = os.environ.get("SENTINEL_SECRET_KEY", "dev-secret-change-me-in-production")
TOKEN_TTL_SECONDS = 8 * 3600  # 8-hour session

ADMIN_USERNAME = os.environ.get("SENTINEL_ADMIN_USER", "admin")
# Default password is intentionally simple for local/demo use — override
# via SENTINEL_ADMIN_PASSWORD before exposing this anywhere but localhost.
ADMIN_PASSWORD = os.environ.get("SENTINEL_ADMIN_PASSWORD", "admin123")

_bearer = HTTPBearer(auto_error=False)


def _hash_password(password: str, salt: str = "sentinel") -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


def verify_credentials(username: str, password: str) -> bool:
    expected_user = ADMIN_USERNAME
    expected_hash = _hash_password(ADMIN_PASSWORD)
    given_hash = _hash_password(password)
    return hmac.compare_digest(username, expected_user) and hmac.compare_digest(given_hash, expected_hash)


def create_token(username: str) -> str:
    payload = {"sub": username, "iat": int(time.time()), "exp": int(time.time()) + TOKEN_TTL_SECONDS}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)):
    """FastAPI dependency: raises 401 unless a valid bearer token is present."""
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    payload = decode_token(creds.credentials)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return payload["sub"]


def verify_ws_token(token: str) -> bool:
    """WebSocket connections can't send an Authorization header from a
    browser, so the frontend passes the token as a query param instead."""
    return decode_token(token) is not None
