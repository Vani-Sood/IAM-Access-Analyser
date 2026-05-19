"""Admin endpoints: audit log listing, signed JSON export, user management."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.analysis.audit import AuditLogger
from app.api.v1.deps import require_admin
from app.auth.hashing import hash_password
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


class UserEntry(BaseModel):
    id: int
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime


class UserListResponse(BaseModel):
    items: list[UserEntry]
    total: int


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    is_admin: bool = False

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


@router.post("/users", response_model=UserEntry, status_code=201)
def create_user(
    body: CreateUserRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserEntry:
    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        is_active=True,
        is_admin=body.is_admin,
        must_change_password=True,
    )
    db.add(user)
    try:
        db.flush()
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered")
    db.refresh(user)
    return UserEntry(id=user.id, email=user.email, is_active=user.is_active,
                     is_admin=user.is_admin, created_at=user.created_at)


@router.get("/users", response_model=UserListResponse)
def list_users(
    pending: bool = Query(default=False),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserListResponse:
    q = db.query(User)
    if pending:
        q = q.filter(User.is_active.is_(False))
    users = q.order_by(User.created_at.desc()).all()
    return UserListResponse(
        items=[UserEntry(id=u.id, email=u.email, is_active=u.is_active,
                         is_admin=u.is_admin, created_at=u.created_at) for u in users],
        total=len(users),
    )


@router.post("/users/{user_id}/activate", response_model=UserEntry)
def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserEntry:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = True
    db.commit()
    return UserEntry(id=user.id, email=user.email, is_active=user.is_active,
                     is_admin=user.is_admin, created_at=user.created_at)


@router.delete("/users/{user_id}", status_code=200)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
    user.is_active = False
    db.commit()
    return {"deactivated": user_id}


@router.get("/audit-log", response_model=AuditLogResponse)
def list_audit_log(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
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
    _: User = Depends(require_admin),
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
