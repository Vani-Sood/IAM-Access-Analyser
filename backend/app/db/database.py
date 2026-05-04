"""SQLAlchemy engine and session factory with lazy initialization."""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

_engine = None
_SessionLocal = None


def _get_engine():
    global _engine
    if _engine is None:
        from app.config import Settings
        settings = Settings()
        _engine = create_engine(settings.database_url, pool_pre_ping=True)
    return _engine


def _get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=_get_engine(), autocommit=False, autoflush=False)
    return _SessionLocal


def init_db() -> None:
    """Create all tables. Used in dev; prod uses Alembic migrations."""
    from app.db.models import Base
    engine = _get_engine()
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        conn.execute(
            __import__("sqlalchemy").text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                "must_change_password BOOLEAN NOT NULL DEFAULT FALSE"
            )
        )
        conn.commit()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a DB session and always closes it."""
    db = _get_session_factory()()
    try:
        yield db
    finally:
        db.close()
