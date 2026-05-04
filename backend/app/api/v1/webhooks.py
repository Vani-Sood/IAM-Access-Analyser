"""Webhook management endpoints — Batch 23."""
from __future__ import annotations

import ipaddress
import json
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import User, Webhook
from app.db.org_repository import OrgRepository
from app.worker.webhook_delivery import deliver_webhook

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

_VALID_EVENTS = {"analysis.complete", "privesc.detected", "compliance.failed"}

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_ssrf_target(url: str) -> bool:
    """Return True if URL targets a private/loopback address or is non-HTTPS."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return True
    host = parsed.hostname or ""
    if host in ("localhost", ""):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        pass
    return False


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RegisterWebhookRequest(BaseModel):
    url: str
    events: list[str]

    @field_validator("url")
    @classmethod
    def url_safe(cls, v: str) -> str:
        if _is_ssrf_target(v):
            raise ValueError(
                "URL must use HTTPS and must not target private/loopback addresses"
            )
        return v

    @field_validator("events")
    @classmethod
    def events_valid(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("At least one event required")
        invalid = set(v) - _VALID_EVENTS
        if invalid:
            raise ValueError(f"Invalid events: {invalid}. Valid: {_VALID_EVENTS}")
        return v


class WebhookCreatedResponse(BaseModel):
    id: int
    url: str
    events: list[str]
    secret: str
    is_active: bool
    created_at: datetime


class WebhookListItem(BaseModel):
    id: int
    url: str
    events: list[str]
    is_active: bool
    failure_count: int
    created_at: datetime


class WebhookListResponse(BaseModel):
    items: list[WebhookListItem]


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

@router.post("", response_model=WebhookCreatedResponse)
def register_webhook(
    req: RegisterWebhookRequest,
    x_org_slug: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WebhookCreatedResponse:
    org = _resolve_org(x_org_slug, current_user, db)
    secret = secrets.token_hex(32)

    hook = Webhook(
        org_id=org.id,
        url=req.url,
        secret=secret,
        events=json.dumps(req.events),
        is_active=True,
        failure_count=0,
        created_at=datetime.now(tz=timezone.utc),
    )
    db.add(hook)
    db.commit()
    db.refresh(hook)

    return WebhookCreatedResponse(
        id=hook.id,
        url=hook.url,
        events=json.loads(hook.events),
        secret=secret,
        is_active=hook.is_active,
        created_at=hook.created_at,
    )


@router.get("", response_model=WebhookListResponse)
def list_webhooks(
    x_org_slug: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WebhookListResponse:
    org = _resolve_org(x_org_slug, current_user, db)
    hooks = db.query(Webhook).filter(Webhook.org_id == org.id).all()
    return WebhookListResponse(
        items=[
            WebhookListItem(
                id=h.id,
                url=h.url,
                events=json.loads(h.events),
                is_active=h.is_active,
                failure_count=h.failure_count,
                created_at=h.created_at,
            )
            for h in hooks
        ]
    )


@router.delete("/{hook_id}", response_model=dict)
def delete_webhook(
    hook_id: int,
    x_org_slug: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    org = _resolve_org(x_org_slug, current_user, db)
    hook = db.query(Webhook).filter(
        Webhook.id == hook_id, Webhook.org_id == org.id
    ).first()
    if hook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    db.delete(hook)
    db.commit()
    return {"deleted": hook_id}


@router.post("/{hook_id}/test", response_model=dict)
def test_webhook(
    hook_id: int,
    x_org_slug: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    org = _resolve_org(x_org_slug, current_user, db)
    hook = db.query(Webhook).filter(
        Webhook.id == hook_id, Webhook.org_id == org.id
    ).first()
    if hook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    deliver_webhook.delay(
        hook_id,
        "analysis.complete",
        {"event": "analysis.complete", "org": org.slug, "data": {"test": True}},
    )
    return {"queued": True, "webhook_id": hook_id}
