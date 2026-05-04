"""Shared FastAPI dependencies for API v1."""
from __future__ import annotations

import hashlib
import re
from typing import Annotated

import jwt as pyjwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.auth.jwt import decode_token
from app.config import Settings
from app.db.database import get_db
from app.db.models import ApiKey, Membership, Organization, User
from app.db.org_repository import OrgRepository

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
    token: str | None = Depends(_oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Accept JWT Bearer token OR ApiKey <key> in Authorization header."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    auth_header: str = authorization or ""

    # ApiKey path
    if auth_header.startswith("ApiKey "):
        raw_key = auth_header[len("ApiKey "):]
        key_hash = _hash_key(raw_key)
        api_key = db.query(ApiKey).filter(
            ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True)
        ).first()
        if api_key is None:
            raise credentials_exc

        from datetime import datetime, timezone
        api_key.last_used_at = datetime.now(tz=timezone.utc)
        db.commit()

        user = db.get(User, api_key.user_id)
        if user is None or not user.is_active:
            raise credentials_exc
        return user

    # JWT Bearer path
    if not token:
        raise credentials_exc

    settings = Settings()
    try:
        payload = decode_token(token, settings.jwt_secret)
    except pyjwt.PyJWTError:
        raise credentials_exc

    if payload.get("type") != "access":
        raise credentials_exc

    email: str | None = payload.get("sub")
    if not email:
        raise credentials_exc

    user = db.query(User).filter(User.email == email).first()
    if user is None or not user.is_active:
        raise credentials_exc
    return user


def resolve_org_membership(
    x_org_slug: str | None,
    current_user: User,
    db: Session,
) -> Membership | None:
    """Return Membership if X-Org-Slug is present and user is a member.

    Raises 404 if org not found, 403 if not a member.
    Returns None if no slug given.
    """
    if not x_org_slug:
        return None
    repo = OrgRepository(db)
    org = repo.get_by_slug(x_org_slug)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    membership = repo.get_membership(org_id=org.id, user_id=current_user.id)
    if membership is None:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    return membership
