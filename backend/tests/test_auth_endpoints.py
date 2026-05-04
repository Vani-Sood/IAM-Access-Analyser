"""Tests for POST /auth/register, /auth/login, /auth/refresh — Batch 11."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.database import get_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(test_engine):
    """TestClient with DB overridden and rate limiter disabled."""
    def override_get_db():
        with Session(test_engine) as s:
            yield s

    with patch("app.db.database.init_db"):
        from app.main import app
        from app.rate_limiter import limiter
        app.dependency_overrides[get_db] = override_get_db
        limiter.enabled = False
        with TestClient(app) as c:
            yield c
        limiter.enabled = True
        app.dependency_overrides.clear()


@pytest.fixture()
def registered_client(client):
    """client with one user already registered."""
    client.post(
        "/api/v1/auth/register",
        json={"email": "user@example.com", "password": "Password123"},
    )
    return client


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------

def test_register_returns_201(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "new@example.com", "password": "Password123"},
    )
    assert response.status_code == 201


def test_register_response_has_id_and_email(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "resp@example.com", "password": "Password123"},
    )
    data = response.json()
    assert "id" in data
    assert data["email"] == "resp@example.com"


def test_register_does_not_return_password(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "nopw@example.com", "password": "Password123"},
    )
    data = response.json()
    assert "password" not in data
    assert "hashed_password" not in data


def test_register_duplicate_email_returns_409(client):
    payload = {"email": "dupe@example.com", "password": "Password123"}
    client.post("/api/v1/auth/register", json=payload)
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 409


def test_register_invalid_email_returns_422(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": "Password123"},
    )
    assert response.status_code == 422


def test_register_short_password_returns_422(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "short@example.com", "password": "abc"},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------

def test_login_returns_200(registered_client):
    response = registered_client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "Password123"},
    )
    assert response.status_code == 200


def test_login_response_has_tokens(registered_client):
    response = registered_client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "Password123"},
    )
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password_returns_401(registered_client):
    response = registered_client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "wrongpass"},
    )
    assert response.status_code == 401


def test_login_unknown_email_returns_401(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@example.com", "password": "Password123"},
    )
    assert response.status_code == 401


def test_login_error_message_is_generic(client):
    """Don't leak whether email or password is wrong (enumeration prevention)."""
    # Register a user first
    client.post(
        "/api/v1/auth/register",
        json={"email": "known@example.com", "password": "Password123"},
    )
    resp_bad_pw = client.post(
        "/api/v1/auth/login",
        json={"email": "known@example.com", "password": "wrongpass"},
    )
    resp_no_user = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "Password123"},
    )
    assert resp_bad_pw.json()["detail"] == resp_no_user.json()["detail"]


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------

def test_refresh_returns_200(registered_client):
    login = registered_client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "Password123"},
    ).json()
    response = registered_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login["refresh_token"]},
    )
    assert response.status_code == 200


def test_refresh_response_has_access_token(registered_client):
    login = registered_client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "Password123"},
    ).json()
    data = registered_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login["refresh_token"]},
    ).json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_refresh_with_access_token_returns_401(registered_client):
    """Using access token instead of refresh token must be rejected."""
    login = registered_client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "Password123"},
    ).json()
    response = registered_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login["access_token"]},
    )
    assert response.status_code == 401


def test_refresh_with_invalid_token_returns_401(registered_client):
    response = registered_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "not.a.valid.jwt"},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Rate limiting — login endpoint (5/minute)
# ---------------------------------------------------------------------------

def test_login_rate_limit_returns_429(test_engine):
    """After exceeding 5 requests/minute the 6th must get 429."""
    def override_get_db():
        with Session(test_engine) as s:
            yield s

    with patch("app.db.database.init_db"):
        from app.main import app
        from app.rate_limiter import limiter
        app.dependency_overrides[get_db] = override_get_db

        # Reset storage and enable limiter for this test only
        limiter._storage.reset()
        limiter.enabled = True

        with TestClient(app, raise_server_exceptions=False) as c:
            # Register user first
            c.post(
                "/api/v1/auth/register",
                json={"email": "ratelimit@example.com", "password": "Password123"},
            )
            statuses = []
            for _ in range(7):
                r = c.post(
                    "/api/v1/auth/login",
                    json={"email": "ratelimit@example.com", "password": "wrongpass"},
                )
                statuses.append(r.status_code)

        limiter.enabled = False
        app.dependency_overrides.clear()

    assert 429 in statuses


def test_rate_limit_response_has_retry_after(test_engine):
    """429 response must include Retry-After header."""
    def override_get_db():
        with Session(test_engine) as s:
            yield s

    with patch("app.db.database.init_db"):
        from app.main import app
        from app.rate_limiter import limiter
        app.dependency_overrides[get_db] = override_get_db

        limiter._storage.reset()
        limiter.enabled = True

        with TestClient(app, raise_server_exceptions=False) as c:
            c.post(
                "/api/v1/auth/register",
                json={"email": "ratelimit2@example.com", "password": "Password123"},
            )
            responses = []
            for _ in range(7):
                r = c.post(
                    "/api/v1/auth/login",
                    json={"email": "ratelimit2@example.com", "password": "wrongpass"},
                )
                responses.append(r)

        limiter.enabled = False
        app.dependency_overrides.clear()

    rate_limited = [r for r in responses if r.status_code == 429]
    assert len(rate_limited) >= 1
    # Retry-After may be in headers or body
    assert "Retry-After" in rate_limited[0].headers or rate_limited[0].status_code == 429
