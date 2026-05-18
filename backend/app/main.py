from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.admin import router as admin_router
from app.api.v1.analyze import router as analyze_router
from app.api.v1.analyses import router as analyses_router
from app.api.v1.apikeys import router as apikeys_router
from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.orgs import router as orgs_router
from app.api.v1.webhooks import router as webhooks_router
from app.rate_limiter import limiter

# Docker: backend mounted at /app, frontend volume at /app/frontend → parent.parent works.
# Local dev: repo root is parent.parent.parent of main.py → check fallback.
_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
if not _FRONTEND_DIR.exists():
    _FRONTEND_DIR = Path(__file__).parent.parent.parent / "frontend"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


def _seed_admin() -> None:
    import os
    from app.db.database import _get_session_factory
    from app.db.models import User
    from app.auth.hashing import hash_password

    admin_email = os.environ.get("ADMIN_EMAIL")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_email or not admin_password:
        return
    db = _get_session_factory()()
    try:
        if not db.query(User).filter(User.email == admin_email).first():
            db.add(User(
                email=admin_email,
                hashed_password=hash_password(admin_password),
                must_change_password=False,
            ))
            db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(application: FastAPI):
    from app.db.database import init_db
    init_db()
    _seed_admin()
    yield
    from app.graph.neo4j_driver import close_driver
    close_driver()


app = FastAPI(
    title="IAM Policy Analyzer",
    version="0.3.0",
    description="AI-powered IAM policy risk scoring and least-privilege suggestions",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(ValidationError)
async def validation_exception_handler(
    request: Request, exc: ValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
    )


app.include_router(auth_router)
app.include_router(analyze_router)
app.include_router(analyses_router)
app.include_router(apikeys_router)
app.include_router(dashboard_router)
app.include_router(orgs_router)
app.include_router(webhooks_router)
app.include_router(admin_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


if _FRONTEND_DIR.exists():
    app.mount(
        "/",
        StaticFiles(directory=str(_FRONTEND_DIR), html=True),
        name="frontend",
    )
