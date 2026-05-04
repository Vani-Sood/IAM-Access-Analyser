"""API Key management endpoints — Batch 23."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import ApiKey, Organization, User
from app.db.org_repository import OrgRepository

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

    @field_validator("scope")
    @classmethod
    def scope_valid(cls, v: str) -> str:
        if v not in _VALID_SCOPES:
            raise ValueError(f"scope must be one of {_VALID_SCOPES}")
        return v


class ApiKeyCreatedResponse(BaseModel):
    id: int
    name: str
    prefix: str
    key: str
    scope: str
    is_active: bool
    created_at: datetime


class ApiKeyListItem(BaseModel):
    id: int
    name: str
    prefix: str
    scope: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None


class ApiKeyListResponse(BaseModel):
    items: list[ApiKeyListItem]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_org(slug: str | None, user: User, db: Session):
    if not slug:
        raise HTTPException(status_code=400, detail="X-Org-Slug header required")
    repo = OrgRepository(db)
    org = repo.get_by_slug(slug)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    membership = repo.get_membership(org_id=org.id, user_id=user.id)
    if membership is None:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    return org


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=ApiKeyCreatedResponse)
def create_api_key(
    req: CreateApiKeyRequest,
    x_org_slug: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApiKeyCreatedResponse:
    org = _resolve_org(x_org_slug, current_user, db)

    raw = _PREFIX + secrets.token_urlsafe(32)
    prefix = raw[:len(_PREFIX) + 8]
    key_hash = _hash_key(raw)

    api_key = ApiKey(
        name=req.name,
        key_prefix=prefix,
        key_hash=key_hash,
        scope=req.scope,
        org_id=org.id,
        user_id=current_user.id,
        is_active=True,
        created_at=datetime.now(tz=timezone.utc),
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
    )


@router.get("", response_model=ApiKeyListResponse)
def list_api_keys(
    x_org_slug: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApiKeyListResponse:
    org = _resolve_org(x_org_slug, current_user, db)

    keys = db.query(ApiKey).filter(ApiKey.org_id == org.id).all()
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
            )
            for k in keys
        ]
    )


@router.delete("/{key_id}", response_model=dict)
def revoke_api_key(
    key_id: int,
    x_org_slug: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    org = _resolve_org(x_org_slug, current_user, db)

    key = db.query(ApiKey).filter(
        ApiKey.id == key_id, ApiKey.org_id == org.id
    ).first()
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found")

    key.is_active = False
    db.commit()
    return {"revoked": key_id}
