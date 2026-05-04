"""Tests for webhook delivery Celery task — Batch 23."""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import Base, Organization, Webhook


@pytest.fixture(scope="module")
def delivery_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture()
def delivery_db(delivery_engine):
    with Session(delivery_engine) as s:
        yield s
        s.rollback()


@pytest.fixture()
def org_with_webhook(delivery_db):
    org = Organization(name="Delivery Org", slug="delivery-org")
    delivery_db.add(org)
    delivery_db.flush()

    hook = Webhook(
        org_id=org.id,
        url="https://example.com/receiver",
        secret="testsecret12345",
        events=json.dumps(["analysis.complete"]),
        is_active=True,
        failure_count=0,
    )
    delivery_db.add(hook)
    delivery_db.commit()
    return org, hook


# ---------------------------------------------------------------------------
# _sign_payload helper
# ---------------------------------------------------------------------------

def test_sign_payload_produces_hmac():
    from app.worker.webhook_delivery import _sign_payload
    body = b'{"event": "analysis.complete"}'
    secret = "mysecret"
    sig = _sign_payload(body, secret)
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"


def test_sign_payload_different_secret_different_sig():
    from app.worker.webhook_delivery import _sign_payload
    body = b'{"event": "test"}'
    sig1 = _sign_payload(body, "secret1")
    sig2 = _sign_payload(body, "secret2")
    assert sig1 != sig2


# ---------------------------------------------------------------------------
# _do_deliver helper
# ---------------------------------------------------------------------------

def test_do_deliver_calls_https_endpoint(org_with_webhook, delivery_db):
    from app.worker.webhook_delivery import _do_deliver
    _, hook = org_with_webhook

    payload = {"event": "analysis.complete", "org": "delivery-org", "data": {}}

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("app.worker.webhook_delivery.requests.post", return_value=mock_resp) as mock_post:
        _do_deliver(hook.id, "analysis.complete", payload, db_session=delivery_db)

    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert call_kwargs[0][0] == "https://example.com/receiver"


def test_do_deliver_sends_hmac_signature(delivery_db):
    from app.worker.webhook_delivery import _do_deliver
    org2 = Organization(name="Sig Org", slug="sig-org-unique")
    delivery_db.add(org2)
    delivery_db.flush()
    hook2 = Webhook(
        org_id=org2.id,
        url="https://example.com/sig",
        secret="sigsecret999",
        events=json.dumps(["analysis.complete"]),
        is_active=True,
        failure_count=0,
    )
    delivery_db.add(hook2)
    delivery_db.commit()

    payload = {"event": "analysis.complete", "org": "sig-org-unique", "data": {}}
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("app.worker.webhook_delivery.requests.post", return_value=mock_resp) as mock_post:
        _do_deliver(hook2.id, "analysis.complete", payload, db_session=delivery_db)

    headers = mock_post.call_args[1]["headers"]
    assert "X-Vani-Signature" in headers
    assert headers["X-Vani-Signature"].startswith("sha256=")


def test_do_deliver_skips_inactive_webhook(delivery_db):
    from app.worker.webhook_delivery import _do_deliver
    org = Organization(name="Skip Org", slug="skip-org")
    delivery_db.add(org)
    delivery_db.flush()

    hook = Webhook(
        org_id=org.id,
        url="https://example.com/skip",
        secret="skip_secret",
        events=json.dumps(["analysis.complete"]),
        is_active=False,
        failure_count=0,
    )
    delivery_db.add(hook)
    delivery_db.commit()

    with patch("app.worker.webhook_delivery.requests.post") as mock_post:
        _do_deliver(hook.id, "analysis.complete", {}, db_session=delivery_db)

    mock_post.assert_not_called()


def test_do_deliver_increments_failure_count_on_error(delivery_db):
    from app.worker.webhook_delivery import _do_deliver
    org3 = Organization(name="Fail Org", slug="fail-org-unique")
    delivery_db.add(org3)
    delivery_db.flush()
    hook3 = Webhook(
        org_id=org3.id,
        url="https://example.com/fail",
        secret="failsecret",
        events=json.dumps(["analysis.complete"]),
        is_active=True,
        failure_count=0,
    )
    delivery_db.add(hook3)
    delivery_db.commit()
    initial_failures = hook3.failure_count

    with patch(
        "app.worker.webhook_delivery.requests.post",
        side_effect=Exception("connection refused"),
    ):
        try:
            _do_deliver(hook3.id, "analysis.complete", {}, db_session=delivery_db)
        except Exception:
            pass

    delivery_db.refresh(hook3)
    assert hook3.failure_count > initial_failures


# ---------------------------------------------------------------------------
# Celery task — deliver_webhook
# ---------------------------------------------------------------------------

def test_deliver_webhook_task_exists():
    from app.worker.webhook_delivery import deliver_webhook
    assert callable(deliver_webhook)


def test_deliver_webhook_task_has_retry_config():
    from app.worker.webhook_delivery import deliver_webhook
    assert deliver_webhook.max_retries == 3


# ---------------------------------------------------------------------------
# Event filtering
# ---------------------------------------------------------------------------

def test_do_deliver_skips_wrong_event(delivery_db):
    """Webhook subscribed only to analysis.complete should not fire for privesc.detected."""
    from app.worker.webhook_delivery import _do_deliver
    org = Organization(name="Filter Org", slug="filter-org")
    delivery_db.add(org)
    delivery_db.flush()

    hook = Webhook(
        org_id=org.id,
        url="https://example.com/filter",
        secret="filter_secret",
        events=json.dumps(["analysis.complete"]),
        is_active=True,
        failure_count=0,
    )
    delivery_db.add(hook)
    delivery_db.commit()

    with patch("app.worker.webhook_delivery.requests.post") as mock_post:
        _do_deliver(hook.id, "privesc.detected", {}, db_session=delivery_db)

    mock_post.assert_not_called()
