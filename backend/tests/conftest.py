"""Shared test fixtures for backend tests."""
from __future__ import annotations

import os

# High rate limit so tests never hit 429
os.environ.setdefault("RATE_LIMIT_PER_HOUR", "10000")
# Pin JWT secret so test tokens verify regardless of .env contents
os.environ["JWT_SECRET"] = "dev-secret-change-me"

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import Base, User


@pytest.fixture(scope="session")
def test_engine():
    """SQLite in-memory engine — StaticPool keeps one connection so all sessions share same DB."""
    eng = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture()
def db_session(test_engine):
    """Transactional session — rolls back after each test."""
    with Session(test_engine) as s:
        yield s
        s.rollback()


@pytest.fixture()
def mock_user() -> User:
    """Fake authenticated user for dependency override."""
    return User(id=1, email="test@example.com", hashed_password="x", is_active=True)
