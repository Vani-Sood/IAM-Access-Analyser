"""API Key management endpoints — Batch 23."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import ApiKey, User

router = APIRouter(prefix="/api/v1/apikeys", tags=["apikeys"])

_VALID_SCOPES = {"read", "readwrite", "admin"}
_PREFIX = "vani_"


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CreateApiKeyRequest(BaseModel):
    name: str
    scope: str
    expires_in_days: int | None = None  # None = never expires

    @field_validator("scope")
    @classmethod
    def scope_valid(cls, v: str) -> str:
        if v not in _VALID_SCOPES:
            raise ValueError(f"scope must be one of {_VALID_SCOPES}")
        return v

    @field_validator("expires_in_days")
    @classmethod
    def expiry_valid(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("expires_in_days must be at least 1")
        return v


class ApiKeyCreatedResponse(BaseModel):
    id: int
    name: str
    prefix: str
    key: str
    scope: str
    is_active: bool
    created_at: datetime
    expires_at: datetime | None


class ApiKeyListItem(BaseModel):
    id: int
    name: str
    prefix: str
    scope: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None


class ApiKeyListResponse(BaseModel):
    items: list[ApiKeyListItem]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=ApiKeyCreatedResponse)
def create_api_key(
    req: CreateApiKeyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApiKeyCreatedResponse:
    raw = _PREFIX + secrets.token_urlsafe(32)
    prefix = raw[:len(_PREFIX) + 8]
    key_hash = _hash_key(raw)

    from datetime import timedelta
    now = datetime.now(tz=timezone.utc)
    expires_at = (now + timedelta(days=req.expires_in_days)) if req.expires_in_days else None

    api_key = ApiKey(
        name=req.name,
        key_prefix=prefix,
        key_hash=key_hash,
        scope=req.scope,
        org_id=None,
        user_id=current_user.id,
        is_active=True,
        created_at=now,
        expires_at=expires_at,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return ApiKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        prefix=prefix,
        key=raw,
        scope=api_key.scope,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
    )


@router.get("", response_model=ApiKeyListResponse)
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApiKeyListResponse:
    keys = db.query(ApiKey).filter(ApiKey.user_id == current_user.id).all()
    return ApiKeyListResponse(
        items=[
            ApiKeyListItem(
                id=k.id,
                name=k.name,
                prefix=k.key_prefix,
                scope=k.scope,
                is_active=k.is_active,
                created_at=k.created_at,
                last_used_at=k.last_used_at,
                expires_at=k.expires_at,
            )
            for k in keys
        ]
    )


@router.delete("/{key_id}", response_model=dict)
def revoke_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    key = db.query(ApiKey).filter(
        ApiKey.id == key_id, ApiKey.user_id == current_user.id
    ).first()
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found")

    key.is_active = False
    db.commit()
    return {"revoked": key_id}
