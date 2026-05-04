"""JWT creation and decoding utilities."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt as pyjwt

_ALGORITHM = "HS256"


def create_access_token(
    sub: str,
    secret: str,
    ttl_minutes: int = 15,
) -> str:
    """Create a short-lived access JWT."""
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": sub,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
    }
    return pyjwt.encode(payload, secret, algorithm=_ALGORITHM)


def create_refresh_token(
    sub: str,
    secret: str,
    ttl_days: int = 7,
) -> str:
    """Create a long-lived refresh JWT."""
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": sub,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=ttl_days),
    }
    return pyjwt.encode(payload, secret, algorithm=_ALGORITHM)


def decode_token(token: str, secret: str) -> dict:
    """Decode and verify *token*; raises jwt.PyJWTError on any failure.

    Only HS256 is accepted — algorithm confusion attacks are prevented.
    """
    return pyjwt.decode(
        token,
        secret,
        algorithms=[_ALGORITHM],
        options={"require": ["exp", "sub", "type"]},
    )
