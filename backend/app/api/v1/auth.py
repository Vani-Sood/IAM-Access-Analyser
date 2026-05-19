"""Auth endpoints: register, login, refresh."""
from __future__ import annotations

import logging

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.v1.deps import require_admin
from app.auth.hashing import hash_password, verify_password
from app.auth.jwt import create_access_token, create_refresh_token, decode_token
from app.config import Settings
from app.db.database import get_db
from app.db.models import User
from app.rate_limiter import limiter

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
logger = logging.getLogger(__name__)

_INVALID_CREDS = "Invalid credentials"


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class RegisterResponse(BaseModel):
    id: int
    email: str


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    must_change_password: bool = False


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)

    @field_validator("new_password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class RefreshRequest(BaseModel):
    refresh_token: str


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/register", response_model=RegisterResponse, status_code=201)
@limiter.limit("3/minute")
def register(
    request: Request,
    body: RegisterRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> RegisterResponse:
    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        is_active=False,
        is_admin=False,
    )
    db.add(user)
    try:
        db.flush()
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    try:
        from app.analysis.audit import AuditLogger
        AuditLogger(db).log(
            "auth.register", {"email": user.email},
            actor_id=user.id, actor_email=user.email,
        )
        db.commit()
    except Exception:
        pass
    return RegisterResponse(id=user.id, email=user.email)


@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
def login(
    request: Request,
    body: LoginRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    settings = Settings()
    user = db.query(User).filter(User.email == body.email).first()

    if user is None or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDS,
        )

    access = create_access_token(
        sub=user.email,
        secret=settings.jwt_secret,
        ttl_minutes=settings.jwt_access_ttl_minutes,
        is_admin=user.is_admin,
    )
    refresh = create_refresh_token(
        sub=user.email,
        secret=settings.jwt_secret,
        ttl_days=settings.jwt_refresh_ttl_days,
    )
    try:
        from app.analysis.audit import AuditLogger
        AuditLogger(db).log(
            "auth.login", {"email": user.email},
            actor_id=user.id, actor_email=user.email,
        )
        db.commit()
    except Exception:
        pass
    return LoginResponse(
        access_token=access,
        refresh_token=refresh,
        must_change_password=user.must_change_password,
    )


@router.post("/change-password", status_code=200)
@limiter.limit("5/minute")
def change_password(
    request: Request,
    body: ChangePasswordRequest,
    db: Session = Depends(get_db),
) -> dict:
    from app.api.v1.deps import get_current_user
    from fastapi.security import OAuth2PasswordBearer
    from fastapi import Request as _Req

    authorization = request.headers.get("Authorization", "")
    token = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else None
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDS)

    settings = Settings()
    try:
        payload = decode_token(token, settings.jwt_secret)
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDS)

    email: str | None = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDS)
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password incorrect")

    user.hashed_password = hash_password(body.new_password)
    user.must_change_password = False
    db.commit()
    return {"message": "Password changed successfully"}


@router.post("/refresh", response_model=RefreshResponse)
@limiter.limit("10/minute")
def refresh(request: Request, body: RefreshRequest) -> RefreshResponse:
    settings = Settings()
    try:
        payload = decode_token(body.refresh_token, settings.jwt_secret)
    except pyjwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDS,
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDS,
        )

    new_access = create_access_token(
        sub=payload["sub"],
        secret=settings.jwt_secret,
        ttl_minutes=settings.jwt_access_ttl_minutes,
    )
    return RefreshResponse(access_token=new_access)
