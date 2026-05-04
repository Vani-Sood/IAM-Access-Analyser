"""Password hashing utilities using bcrypt directly."""
from __future__ import annotations

import bcrypt


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain*."""
    return bcrypt.hashpw(
        plain.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True when *plain* matches *hashed*."""
    try:
        return bcrypt.checkpw(
            plain.encode("utf-8"), hashed.encode("utf-8")
        )
    except Exception:
        return False
