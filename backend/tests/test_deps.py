"""Tests for get_current_user FastAPI dependency — Batch 11."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.auth.hashing import hash_password
from app.auth.jwt import create_access_token, create_refresh_token
from app.db.database import get_db
from app.db.models import User

# Must match Settings default so tokens verify without patching
_SECRET = "dev-secret-change-me"
_EMAIL = "deptest@example.com"

SIMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
}

MOCK_LLM = '{"least_privilege_policy": null, "changes": []}'


@pytest.fixture(scope="module")
def seeded_user(test_engine):
    """Insert a test user once per module; return it."""
    with Session(test_engine) as s:
        existing = s.query(User).filter(User.email == _EMAIL).first()
        if existing:
            return existing
        user = User(
            email=_EMAIL,
            hashed_password=hash_password("Password1!"),
            is_active=True,
        )
        s.add(user)
        s.commit()
        s.refresh(user)
        return user


@pytest.fixture()
def seeded_client(test_engine, seeded_user):
    """Real TestClient; get_current_user NOT overridden, get_db overridden."""
    def override_get_db():
        with Session(test_engine) as s:
            yield s

    with (
        patch("app.db.database.init_db"),
        patch("app.ai.llm_client.call_llm", return_value=MOCK_LLM),
    ):
        from app.main import app
        app.dependency_overrides[get_db] = override_get_db
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.clear()


# ── Integration tests (via HTTP) ─────────────────────────────────────────────

def test_analyze_requires_auth_no_header(seeded_client):
    resp = seeded_client.post(
        "/api/v1/analyze",
        json={"mode": "json", "policy": SIMPLE_POLICY},
    )
    assert resp.status_code == 401


def test_analyze_invalid_token_401(seeded_client):
    resp = seeded_client.post(
        "/api/v1/analyze",
        json={"mode": "json", "policy": SIMPLE_POLICY},
        headers={"Authorization": "Bearer not.a.valid.token"},
    )
    assert resp.status_code == 401


def test_analyze_valid_token_200(seeded_client):
    token = create_access_token(sub=_EMAIL, secret=_SECRET)
    resp = seeded_client.post(
        "/api/v1/analyze",
        json={"mode": "json", "policy": SIMPLE_POLICY},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "id" in resp.json()


def test_analyze_refresh_token_rejected(seeded_client):
    """Refresh tokens must not be accepted by the analyze endpoint."""
    token = create_refresh_token(sub=_EMAIL, secret=_SECRET)
    resp = seeded_client.post(
        "/api/v1/analyze",
        json={"mode": "json", "policy": SIMPLE_POLICY},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


# ── Unit tests (call dependency directly) ───────────────────────────────────

def test_get_current_user_valid(test_engine, seeded_user):
    token = create_access_token(sub=_EMAIL, secret=_SECRET)
    with Session(test_engine) as s:
        user = get_current_user(token=token, db=s)
    assert user.email == _EMAIL
    assert user.is_active is True


def test_get_current_user_wrong_secret(test_engine, seeded_user):
    token = create_access_token(sub=_EMAIL, secret="wrong-secret")
    with Session(test_engine) as s, pytest.raises(HTTPException) as exc:
        get_current_user(token=token, db=s)
    assert exc.value.status_code == 401


def test_get_current_user_refresh_token_rejected(test_engine, seeded_user):
    token = create_refresh_token(sub=_EMAIL, secret=_SECRET)
    with Session(test_engine) as s, pytest.raises(HTTPException) as exc:
        get_current_user(token=token, db=s)
    assert exc.value.status_code == 401


def test_get_current_user_nonexistent_user(test_engine):
    token = create_access_token(sub="ghost@example.com", secret=_SECRET)
    with Session(test_engine) as s, pytest.raises(HTTPException) as exc:
        get_current_user(token=token, db=s)
    assert exc.value.status_code == 401


def test_get_current_user_inactive_user(test_engine):
    inactive_email = "inactive_dep@example.com"
    with Session(test_engine) as s:
        existing = s.query(User).filter(User.email == inactive_email).first()
        if not existing:
            s.add(User(
                email=inactive_email,
                hashed_password=hash_password("Password1!"),
                is_active=False,
            ))
            s.commit()

    token = create_access_token(sub=inactive_email, secret=_SECRET)
    with Session(test_engine) as s, pytest.raises(HTTPException) as exc:
        get_current_user(token=token, db=s)
    assert exc.value.status_code == 401
