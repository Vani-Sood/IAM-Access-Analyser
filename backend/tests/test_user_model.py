"""Tests for the User SQLAlchemy model — Batch 11."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine():
    eng = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    from app.db.models import Base
    Base.metadata.create_all(eng)
    return eng


# ---------------------------------------------------------------------------
# 1. Model import
# ---------------------------------------------------------------------------

def test_user_model_importable():
    """User model can be imported from app.db.models."""
    from app.db.models import User  # noqa: F401
    assert User is not None


def test_user_model_has_id():
    from app.db.models import User
    assert hasattr(User, "id")


def test_user_model_has_email():
    from app.db.models import User
    assert hasattr(User, "email")


def test_user_model_has_hashed_password():
    from app.db.models import User
    assert hasattr(User, "hashed_password")


def test_user_model_has_created_at():
    from app.db.models import User
    assert hasattr(User, "created_at")


def test_user_model_has_is_active():
    from app.db.models import User
    assert hasattr(User, "is_active")


# ---------------------------------------------------------------------------
# 2. Table creation
# ---------------------------------------------------------------------------

def test_users_table_created_in_metadata():
    from app.db.models import Base
    assert "users" in Base.metadata.tables


# ---------------------------------------------------------------------------
# 3. CRUD via session
# ---------------------------------------------------------------------------

@pytest.fixture()
def session():
    eng = _make_engine()
    with Session(eng) as s:
        yield s
        s.rollback()


def test_can_insert_and_retrieve_user(session):
    from app.db.models import User
    user = User(email="test@example.com", hashed_password="hashed_pw_here")
    session.add(user)
    session.flush()

    fetched = session.get(User, user.id)
    assert fetched is not None
    assert fetched.email == "test@example.com"


def test_user_id_autoincrement(session):
    from app.db.models import User
    u1 = User(email="a@example.com", hashed_password="pw1")
    u2 = User(email="b@example.com", hashed_password="pw2")
    session.add_all([u1, u2])
    session.flush()
    assert u2.id == u1.id + 1


def test_user_is_active_defaults_true(session):
    from app.db.models import User
    user = User(email="active@example.com", hashed_password="pw")
    session.add(user)
    session.flush()
    assert user.is_active is True


def test_user_email_unique_constraint(session):
    from app.db.models import User
    from sqlalchemy.exc import IntegrityError
    u1 = User(email="dupe@example.com", hashed_password="pw1")
    u2 = User(email="dupe@example.com", hashed_password="pw2")
    session.add_all([u1, u2])
    with pytest.raises(IntegrityError):
        session.flush()


def test_user_hashed_password_not_plaintext(session):
    """Ensure stored value is not the literal plaintext 'secret'."""
    from app.db.models import User
    user = User(email="sec@example.com", hashed_password="$2b$12$FAKEHASHVALUE")
    session.add(user)
    session.flush()
    fetched = session.get(User, user.id)
    assert fetched.hashed_password != "secret"
    assert fetched.hashed_password.startswith("$")
