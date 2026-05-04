"""Tests for API Key management endpoints — Batch 23."""
from __future__ import annotations

import hashlib
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import ApiKey, Organization, Membership, User


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(test_engine):
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
def auth_client(client):
    """Registered + logged-in client returning (client, token)."""
    client.post("/api/v1/auth/register", json={"email": "keyuser@example.com", "password": "KeyPass1"})
    resp = client.post("/api/v1/auth/login", json={"email": "keyuser@example.com", "password": "KeyPass1"})
    token = resp.json()["access_token"]
    return client, token


@pytest.fixture()
def org_client(auth_client, test_engine):
    """Client with org created; returns (client, token, slug)."""
    client, token = auth_client
    client.post(
        "/api/v1/orgs",
        json={"name": "Key Org", "slug": "key-org"},
        headers={"Authorization": f"Bearer {token}"},
    )
    return client, token, "key-org"


# ---------------------------------------------------------------------------
# POST /api/v1/apikeys — create
# ---------------------------------------------------------------------------

def test_create_apikey_returns_200(org_client):
    client, token, slug = org_client
    resp = client.post(
        "/api/v1/apikeys",
        json={"name": "CI Key", "scope": "read"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 200


def test_create_apikey_response_has_full_key(org_client):
    client, token, slug = org_client
    resp = client.post(
        "/api/v1/apikeys",
        json={"name": "Deploy Key", "scope": "readwrite"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    data = resp.json()
    assert "key" in data
    assert len(data["key"]) > 20


def test_create_apikey_response_has_prefix(org_client):
    client, token, slug = org_client
    resp = client.post(
        "/api/v1/apikeys",
        json={"name": "Admin Key", "scope": "admin"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    data = resp.json()
    assert "prefix" in data
    assert data["key"].startswith(data["prefix"])


def test_create_apikey_invalid_scope_rejected(org_client):
    client, token, slug = org_client
    resp = client.post(
        "/api/v1/apikeys",
        json={"name": "Bad Key", "scope": "superadmin"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 422


def test_create_apikey_requires_org_slug(auth_client):
    client, token = auth_client
    resp = client.post(
        "/api/v1/apikeys",
        json={"name": "No Org Key", "scope": "read"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


def test_create_apikey_requires_auth(client):
    resp = client.post("/api/v1/apikeys", json={"name": "Anon Key", "scope": "read"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/v1/apikeys — list
# ---------------------------------------------------------------------------

def test_list_apikeys_returns_200(org_client):
    client, token, slug = org_client
    resp = client.get(
        "/api/v1/apikeys",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 200


def test_list_apikeys_shows_prefix_not_full_key(org_client):
    client, token, slug = org_client
    create_resp = client.post(
        "/api/v1/apikeys",
        json={"name": "List Test Key", "scope": "read"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    full_key = create_resp.json()["key"]

    list_resp = client.get(
        "/api/v1/apikeys",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    items = list_resp.json()["items"]
    keys_in_list = [i.get("key", "") for i in items]
    assert full_key not in keys_in_list


def test_list_apikeys_has_metadata(org_client):
    client, token, slug = org_client
    client.post(
        "/api/v1/apikeys",
        json={"name": "Meta Key", "scope": "read"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    resp = client.get(
        "/api/v1/apikeys",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    item = resp.json()["items"][0]
    assert "id" in item
    assert "name" in item
    assert "scope" in item
    assert "prefix" in item
    assert "is_active" in item
    assert "created_at" in item


# ---------------------------------------------------------------------------
# DELETE /api/v1/apikeys/{id} — revoke
# ---------------------------------------------------------------------------

def test_revoke_apikey_returns_200(org_client):
    client, token, slug = org_client
    create_resp = client.post(
        "/api/v1/apikeys",
        json={"name": "Revoke Me", "scope": "read"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    key_id = create_resp.json()["id"]
    resp = client.delete(
        f"/api/v1/apikeys/{key_id}",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 200


def test_revoke_apikey_sets_inactive(org_client):
    client, token, slug = org_client
    create_resp = client.post(
        "/api/v1/apikeys",
        json={"name": "Deactivate Me", "scope": "read"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    key_id = create_resp.json()["id"]
    client.delete(
        f"/api/v1/apikeys/{key_id}",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    list_resp = client.get(
        "/api/v1/apikeys",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    items = list_resp.json()["items"]
    target = next((i for i in items if i["id"] == key_id), None)
    assert target is not None
    assert target["is_active"] is False


def test_revoke_nonexistent_key_returns_404(org_client):
    client, token, slug = org_client
    resp = client.delete(
        "/api/v1/apikeys/999999",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API Key authentication
# ---------------------------------------------------------------------------

def test_apikey_auth_allows_access_to_analyses(org_client):
    client, token, slug = org_client
    create_resp = client.post(
        "/api/v1/apikeys",
        json={"name": "Auth Test Key", "scope": "read"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    api_key = create_resp.json()["key"]

    resp = client.get(
        "/api/v1/analyses",
        headers={"Authorization": f"ApiKey {api_key}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 200


def test_invalid_apikey_returns_401(client):
    resp = client.get(
        "/api/v1/analyses",
        headers={"Authorization": "ApiKey vani_invalidkey123"},
    )
    assert resp.status_code == 401


def test_revoked_apikey_returns_401(org_client):
    client, token, slug = org_client
    create_resp = client.post(
        "/api/v1/apikeys",
        json={"name": "Revoke Auth Key", "scope": "read"},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    data = create_resp.json()
    api_key = data["key"]
    key_id = data["id"]

    client.delete(
        f"/api/v1/apikeys/{key_id}",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )

    resp = client.get(
        "/api/v1/analyses",
        headers={"Authorization": f"ApiKey {api_key}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 401
