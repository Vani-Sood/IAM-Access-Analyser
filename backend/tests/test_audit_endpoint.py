"""Tests for GET /admin/audit-log endpoint — Batch 21."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import User

SIMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}
    ],
}

MOCK_LLM = '{"least_privilege_policy":{"Version":"2012-10-17","Statement":[]},"changes":[]}'


def _make_sync_delay(engine, mock_llm):
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def _delay(analysis_id, mode, policy_data, role_arn, cloud="aws"):
        from app.worker.tasks import run_analysis

        db = factory()
        try:
            with patch("app.ai.llm_client.call_llm", return_value=mock_llm):
                run_analysis(analysis_id, mode, policy_data, role_arn, db_session=db)
            db.commit()
        finally:
            db.close()
        m = MagicMock()
        m.id = "test-task-audit"
        return m

    return _delay


@pytest.fixture()
def client(test_engine, mock_user):
    def override_db():
        with Session(test_engine) as s:
            yield s

    with (
        patch("app.db.database.init_db"),
        patch(
            "app.worker.tasks.analyze_policy_task.delay",
            side_effect=_make_sync_delay(test_engine, MOCK_LLM),
        ),
    ):
        from app.main import app

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_current_user] = lambda: mock_user
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.clear()


# ── Auth ──────────────────────────────────────────────────────────────────────


def test_audit_log_requires_auth():
    with patch("app.db.database.init_db"):
        from app.main import app

        with TestClient(app) as c:
            resp = c.get("/api/v1/admin/audit-log")
    assert resp.status_code == 401


def test_audit_export_requires_auth():
    with patch("app.db.database.init_db"):
        from app.main import app

        with TestClient(app) as c:
            resp = c.get("/api/v1/admin/audit-log/export")
    assert resp.status_code == 401


# ── List endpoint ─────────────────────────────────────────────────────────────


def test_audit_log_returns_200(client):
    resp = client.get("/api/v1/admin/audit-log")
    assert resp.status_code == 200


def test_audit_log_has_required_fields(client):
    data = client.get("/api/v1/admin/audit-log").json()
    for key in ("items", "total", "limit", "offset"):
        assert key in data, f"missing key: {key}"


def test_audit_log_items_is_list(client):
    assert isinstance(client.get("/api/v1/admin/audit-log").json()["items"], list)


def test_audit_log_item_has_fields(client):
    # Create an analysis to generate an audit entry
    client.post("/api/v1/analyze", json={"mode": "json", "policy": SIMPLE_POLICY})
    data = client.get("/api/v1/admin/audit-log").json()
    if data["items"]:
        item = data["items"][0]
        for key in ("id", "event_type", "timestamp", "entry_hash"):
            assert key in item, f"missing key: {key}"


def test_audit_log_records_analyze_create(client):
    client.post("/api/v1/analyze", json={"mode": "json", "policy": SIMPLE_POLICY})
    data = client.get("/api/v1/admin/audit-log").json()
    types = [i["event_type"] for i in data["items"]]
    assert any("analyze" in t for t in types)


def test_audit_log_pagination_limit(client):
    data = client.get("/api/v1/admin/audit-log?limit=1").json()
    assert len(data["items"]) <= 1
    assert data["limit"] == 1


def test_audit_log_pagination_offset(client):
    # Create entries
    for _ in range(3):
        client.post("/api/v1/analyze", json={"mode": "json", "policy": SIMPLE_POLICY})
    resp0 = client.get("/api/v1/admin/audit-log?limit=1&offset=0").json()
    resp1 = client.get("/api/v1/admin/audit-log?limit=1&offset=1").json()
    if resp0["items"] and resp1["items"]:
        assert resp0["items"][0]["id"] != resp1["items"][0]["id"]


def test_audit_log_filter_by_event_type(client):
    client.post("/api/v1/analyze", json={"mode": "json", "policy": SIMPLE_POLICY})
    data = client.get("/api/v1/admin/audit-log?event_type=analyze.create").json()
    for item in data["items"]:
        assert item["event_type"] == "analyze.create"


def test_audit_log_filter_unknown_type_returns_empty(client):
    data = client.get("/api/v1/admin/audit-log?event_type=no.such.event.xyz").json()
    assert data["items"] == []
    assert data["total"] == 0


def test_audit_log_total_gte_items_count(client):
    data = client.get("/api/v1/admin/audit-log").json()
    assert data["total"] >= len(data["items"])


# ── Export endpoint ───────────────────────────────────────────────────────────


def test_audit_export_returns_200(client):
    resp = client.get("/api/v1/admin/audit-log/export")
    assert resp.status_code == 200


def test_audit_export_content_type_json(client):
    resp = client.get("/api/v1/admin/audit-log/export")
    assert "application/json" in resp.headers["content-type"]


def test_audit_export_has_required_fields(client):
    data = client.get("/api/v1/admin/audit-log/export").json()
    for key in ("exported_at", "entries", "chain_valid", "signature"):
        assert key in data, f"missing key: {key}"


def test_audit_export_chain_valid_is_bool(client):
    data = client.get("/api/v1/admin/audit-log/export").json()
    assert isinstance(data["chain_valid"], bool)


def test_audit_export_entries_is_list(client):
    assert isinstance(client.get("/api/v1/admin/audit-log/export").json()["entries"], list)


def test_audit_export_signature_is_string(client):
    sig = client.get("/api/v1/admin/audit-log/export").json()["signature"]
    assert isinstance(sig, str) and len(sig) > 0


def test_audit_export_content_disposition(client):
    resp = client.get("/api/v1/admin/audit-log/export")
    cd = resp.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert ".json" in cd


# ── Auth event logging ────────────────────────────────────────────────────────


def test_audit_login_event_logged(test_engine, mock_user):
    """Successful login should appear in audit log as auth.login."""

    def override_db():
        with Session(test_engine) as s:
            yield s

    with patch("app.db.database.init_db"):
        from app.main import app

        app.dependency_overrides[get_db] = override_db

        # Insert a real user in DB to log in with
        with Session(test_engine) as s:
            from app.auth.hashing import hash_password

            existing = s.query(User).filter(User.email == "audit_login@test.com").first()
            if not existing:
                u = User(email="audit_login@test.com", hashed_password=hash_password("Test1234!"), is_active=True)
                s.add(u)
                s.commit()

        with TestClient(app) as c:
            c.post("/api/v1/auth/login", json={"email": "audit_login@test.com", "password": "Test1234!"})

        # Now check audit log (override auth for reading)
        app.dependency_overrides[get_current_user] = lambda: mock_user
        with TestClient(app) as c:
            data = c.get("/api/v1/admin/audit-log?event_type=auth.login").json()
        app.dependency_overrides.clear()

    types = [i["event_type"] for i in data["items"]]
    assert "auth.login" in types


def test_audit_register_event_logged(test_engine, mock_user):
    """Successful register should appear in audit log as auth.register."""

    def override_db():
        with Session(test_engine) as s:
            yield s

    with patch("app.db.database.init_db"):
        from app.main import app

        app.dependency_overrides[get_db] = override_db
        with TestClient(app) as c:
            c.post(
                "/api/v1/auth/register",
                json={"email": "audit_reg_unique@test.com", "password": "Test1234!"},
            )

        app.dependency_overrides[get_current_user] = lambda: mock_user
        with TestClient(app) as c:
            data = c.get("/api/v1/admin/audit-log?event_type=auth.register").json()
        app.dependency_overrides.clear()

    types = [i["event_type"] for i in data["items"]]
    assert "auth.register" in types
