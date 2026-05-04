"""Tests for Webhook management endpoints — Batch 23."""
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
    client.post("/api/v1/auth/register", json={"email": "webhookuser@example.com", "password": "WebPass1"})
    resp = client.post("/api/v1/auth/login", json={"email": "webhookuser@example.com", "password": "WebPass1"})
    token = resp.json()["access_token"]
    return client, token


@pytest.fixture()
def org_client(auth_client):
    client, token = auth_client
    client.post(
        "/api/v1/orgs",
        json={"name": "Webhook Org", "slug": "webhook-org"},
        headers={"Authorization": f"Bearer {token}"},
    )
    return client, token, "webhook-org"


# ---------------------------------------------------------------------------
# POST /api/v1/webhooks — register
# ---------------------------------------------------------------------------

def test_register_webhook_returns_200(org_client):
    client, token, slug = org_client
    resp = client.post(
        "/api/v1/webhooks",
        json={
            "url": "https://example.com/hook",
            "events": ["analysis.complete"],
        },
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 200


def test_register_webhook_response_has_secret(org_client):
    client, token, slug = org_client
    resp = client.post(
        "/api/v1/webhooks",
        json={
            "url": "https://example.com/hook2",
            "events": ["analysis.complete", "privesc.detected"],
        },
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    data = resp.json()
    assert "secret" in data
    assert len(data["secret"]) > 10


def test_register_webhook_secret_not_in_list(org_client):
    """Secret must never appear in list responses."""
    client, token, slug = org_client
    create_resp = client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/hook3", "events": ["analysis.complete"]},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    secret = create_resp.json()["secret"]

    list_resp = client.get(
        "/api/v1/webhooks",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    import json
    assert secret not in json.dumps(list_resp.json())


def test_register_webhook_invalid_event_rejected(org_client):
    client, token, slug = org_client
    resp = client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/hook", "events": ["invalid.event"]},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 422


def test_register_webhook_empty_events_rejected(org_client):
    client, token, slug = org_client
    resp = client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/hook", "events": []},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 422


def test_register_webhook_requires_auth(client):
    resp = client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/hook", "events": ["analysis.complete"]},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_url", [
    "http://localhost/hook",
    "https://127.0.0.1/hook",
    "http://10.0.0.1/hook",
    "https://192.168.1.1/hook",
    "http://172.16.0.1/hook",
    "http://169.254.169.254/latest/meta-data/",
    "ftp://example.com/hook",
    "http://example.com/hook",  # HTTP not HTTPS
])
def test_register_webhook_ssrf_blocked(org_client, bad_url):
    client, token, slug = org_client
    resp = client.post(
        "/api/v1/webhooks",
        json={"url": bad_url, "events": ["analysis.complete"]},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /api/v1/webhooks — list
# ---------------------------------------------------------------------------

def test_list_webhooks_returns_200(org_client):
    client, token, slug = org_client
    resp = client.get(
        "/api/v1/webhooks",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 200


def test_list_webhooks_has_items(org_client):
    client, token, slug = org_client
    client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/listed", "events": ["analysis.complete"]},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    resp = client.get(
        "/api/v1/webhooks",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    data = resp.json()
    assert "items" in data
    assert len(data["items"]) >= 1


def test_list_webhooks_item_has_metadata(org_client):
    client, token, slug = org_client
    client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/meta", "events": ["privesc.detected"]},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    resp = client.get(
        "/api/v1/webhooks",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    item = resp.json()["items"][0]
    assert "id" in item
    assert "url" in item
    assert "events" in item
    assert "is_active" in item
    assert "failure_count" in item
    assert "secret" not in item


# ---------------------------------------------------------------------------
# DELETE /api/v1/webhooks/{id} — remove
# ---------------------------------------------------------------------------

def test_delete_webhook_returns_200(org_client):
    client, token, slug = org_client
    create_resp = client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/delete-me", "events": ["analysis.complete"]},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    hook_id = create_resp.json()["id"]
    resp = client.delete(
        f"/api/v1/webhooks/{hook_id}",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 200


def test_delete_webhook_removes_from_list(org_client):
    client, token, slug = org_client
    create_resp = client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/remove-from-list", "events": ["analysis.complete"]},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    hook_id = create_resp.json()["id"]
    client.delete(
        f"/api/v1/webhooks/{hook_id}",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    list_resp = client.get(
        "/api/v1/webhooks",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    ids = [i["id"] for i in list_resp.json()["items"]]
    assert hook_id not in ids


def test_delete_nonexistent_webhook_returns_404(org_client):
    client, token, slug = org_client
    resp = client.delete(
        "/api/v1/webhooks/999999",
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/webhooks/{id}/test — test ping
# ---------------------------------------------------------------------------

def test_ping_webhook_returns_200(org_client):
    client, token, slug = org_client
    create_resp = client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/ping", "events": ["analysis.complete"]},
        headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
    )
    hook_id = create_resp.json()["id"]

    with patch("app.api.v1.webhooks.deliver_webhook") as mock_task:
        mock_task.delay.return_value = None
        resp = client.post(
            f"/api/v1/webhooks/{hook_id}/test",
            headers={"Authorization": f"Bearer {token}", "X-Org-Slug": slug},
        )
    assert resp.status_code == 200
