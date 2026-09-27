"""tests/test_auth.py — unit tests for backend/app/auth.py"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SENTINEL_ADMIN_USER", "admin")
os.environ.setdefault("SENTINEL_ADMIN_PASSWORD", "admin123")

from backend.app.auth import verify_credentials, create_token, decode_token, verify_ws_token


def test_verify_credentials_correct():
    assert verify_credentials("admin", "admin123") is True


def test_verify_credentials_wrong_password():
    assert verify_credentials("admin", "wrong-password") is False


def test_verify_credentials_wrong_username():
    assert verify_credentials("not-admin", "admin123") is False


def test_create_and_decode_token_roundtrip():
    token = create_token("admin")
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "admin"


def test_decode_token_rejects_garbage():
    assert decode_token("not-a-real-token") is None


def test_verify_ws_token_valid_and_invalid():
    token = create_token("admin")
    assert verify_ws_token(token) is True
    assert verify_ws_token("garbage") is False
    assert verify_ws_token("") is False
