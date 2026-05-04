"""Admin endpoints: audit log listing and signed JSON export."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.analysis.audit import AuditLogger
from app.api.v1.deps import get_current_user
from app.config import Settings
from app.db.database import get_db
from app.db.models import User

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class AuditEntry(BaseModel):
    id: int
    event_type: str
    actor_id: int | None
    actor_email: str | None
    payload: dict
    timestamp: datetime
    prev_hash: str
    entry_hash: str


class AuditLogResponse(BaseModel):
    items: list[AuditEntry]
    total: int
    limit: int
    offset: int


@router.get("/audit-log", response_model=AuditLogResponse)
def list_audit_log(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AuditLogResponse:
    logger = AuditLogger(db)
    entries, total = logger.list_entries(limit=limit, offset=offset, event_type=event_type)

    items = [
        AuditEntry(
            id=e.id,
            event_type=e.event_type,
            actor_id=e.actor_id,
            actor_email=e.actor_email,
            payload=__import__("json").loads(e.payload_json),
            timestamp=e.timestamp,
            prev_hash=e.prev_hash,
            entry_hash=e.entry_hash,
        )
        for e in entries
    ]
    return AuditLogResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/audit-log/export")
def export_audit_log(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Response:
    settings = Settings()
    logger = AuditLogger(db)
    export = logger.export_signed(settings.jwt_secret)
    body = json.dumps(export, default=str)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="audit_log_{ts}.json"'
        },
    )
