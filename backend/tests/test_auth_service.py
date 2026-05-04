"""Tests for hashing utilities and JWT helpers — Batch 11."""
from __future__ import annotations

import time
from datetime import timedelta

import pytest


# ---------------------------------------------------------------------------
# Password hashing (app/auth/hashing.py)
# ---------------------------------------------------------------------------

def test_hashing_importable():
    from app.auth.hashing import hash_password, verify_password  # noqa: F401


def test_hash_password_returns_string():
    from app.auth.hashing import hash_password
    result = hash_password("mysecret")
    assert isinstance(result, str)


def test_hash_password_not_plaintext():
    from app.auth.hashing import hash_password
    result = hash_password("mysecret")
    assert result != "mysecret"


def test_hash_password_bcrypt_prefix():
    """bcrypt hashes start with $2b$."""
    from app.auth.hashing import hash_password
    result = hash_password("mysecret")
    assert result.startswith("$2")


def test_verify_password_correct():
    from app.auth.hashing import hash_password, verify_password
    hashed = hash_password("correct")
    assert verify_password("correct", hashed) is True


def test_verify_password_wrong():
    from app.auth.hashing import hash_password, verify_password
    hashed = hash_password("correct")
    assert verify_password("wrong", hashed) is False


def test_hash_same_password_different_hashes():
    """Salted hashing: same plaintext produces different hashes."""
    from app.auth.hashing import hash_password
    h1 = hash_password("same")
    h2 = hash_password("same")
    assert h1 != h2


# ---------------------------------------------------------------------------
# JWT utils (app/auth/jwt.py)
# ---------------------------------------------------------------------------

SECRET = "test-secret-key-for-unit-tests"


def test_jwt_importable():
    from app.auth.jwt import create_access_token, create_refresh_token, decode_token  # noqa: F401


def test_create_access_token_returns_string():
    from app.auth.jwt import create_access_token
    token = create_access_token(sub="user@example.com", secret=SECRET)
    assert isinstance(token, str)


def test_create_access_token_decodable():
    from app.auth.jwt import create_access_token, decode_token
    token = create_access_token(sub="user@example.com", secret=SECRET)
    payload = decode_token(token, SECRET)
    assert payload["sub"] == "user@example.com"


def test_access_token_type_claim():
    from app.auth.jwt import create_access_token, decode_token
    token = create_access_token(sub="u@example.com", secret=SECRET)
    payload = decode_token(token, SECRET)
    assert payload.get("type") == "access"


def test_create_refresh_token_returns_string():
    from app.auth.jwt import create_refresh_token
    token = create_refresh_token(sub="user@example.com", secret=SECRET)
    assert isinstance(token, str)


def test_refresh_token_type_claim():
    from app.auth.jwt import create_refresh_token, decode_token
    token = create_refresh_token(sub="u@example.com", secret=SECRET)
    payload = decode_token(token, SECRET)
    assert payload.get("type") == "refresh"


def test_decode_token_wrong_secret_raises():
    from app.auth.jwt import create_access_token, decode_token
    token = create_access_token(sub="u@example.com", secret=SECRET)
    with pytest.raises(Exception):
        decode_token(token, "wrong-secret")


def test_decode_token_expired_raises():
    from app.auth.jwt import create_access_token, decode_token
    # TTL of -1 minutes → already expired
    token = create_access_token(sub="u@example.com", secret=SECRET, ttl_minutes=-1)
    with pytest.raises(Exception):
        decode_token(token, SECRET)


def test_decode_token_invalid_string_raises():
    from app.auth.jwt import decode_token
    with pytest.raises(Exception):
        decode_token("not.a.jwt", SECRET)


def test_decode_token_rejects_none_algorithm():
    """Token signed with 'none' algorithm must be rejected."""
    import jwt as pyjwt
    from app.auth.jwt import decode_token
    payload = {"sub": "evil@example.com", "type": "access"}
    # pyjwt doesn't allow signing with "none" — create a raw unsigned token
    header = pyjwt.utils.base64url_encode(b'{"alg":"none","typ":"JWT"}').decode()
    body = pyjwt.utils.base64url_encode(b'{"sub":"evil@example.com"}').decode()
    bad_token = f"{header}.{body}."
    with pytest.raises(Exception):
        decode_token(bad_token, SECRET)


def test_access_token_has_exp_claim():
    import jwt as pyjwt
    from app.auth.jwt import create_access_token
    token = create_access_token(sub="u@example.com", secret=SECRET)
    payload = pyjwt.decode(token, SECRET, algorithms=["HS256"])
    assert "exp" in payload


def test_refresh_token_longer_ttl_than_access():
    """Refresh token exp must be later than access token exp."""
    import jwt as pyjwt
    from app.auth.jwt import create_access_token, create_refresh_token
    access = create_access_token(sub="u@example.com", secret=SECRET)
    refresh = create_refresh_token(sub="u@example.com", secret=SECRET)
    access_exp = pyjwt.decode(access, SECRET, algorithms=["HS256"])["exp"]
    refresh_exp = pyjwt.decode(refresh, SECRET, algorithms=["HS256"])["exp"]
    assert refresh_exp > access_exp
