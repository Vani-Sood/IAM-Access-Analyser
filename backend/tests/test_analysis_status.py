"""Tests for GET /analyses/{id}/status endpoint — Batch 14."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import Analysis

SIMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}
    ],
}

HIGH_RISK_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
}

MOCK_LLM = """{
  "least_privilege_policy": {"Version": "2012-10-17", "Statement": []},
  "changes": []
}"""


def _make_sync_delay(test_engine, mock_llm):
    """Return a delay() side-effect that runs run_analysis synchronously."""
    factory = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)

    def _delay(analysis_id, mode, policy_data, role_arn, cloud="aws"):
        from app.worker.tasks import run_analysis
        db = factory()
        try:
            with patch("app.ai.llm_client.call_llm", return_value=mock_llm):
                run_analysis(analysis_id, mode, policy_data, role_arn, db_session=db)
            db.commit()
        finally:
            db.close()
        mock_task = MagicMock()
        mock_task.id = "test-task-sync"
        return mock_task

    return _delay


@pytest.fixture()
def client(test_engine, mock_user):
    def override_get_db():
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
        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_current_user] = lambda: mock_user
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.clear()


def _wrap(policy):
    return {"mode": "json", "policy": policy}


def test_status_returns_200_for_valid_id(client):
    post = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    aid = post.json()["id"]
    response = client.get(f"/api/v1/analyses/{aid}/status")
    assert response.status_code == 200


def test_status_returns_404_for_unknown(client):
    response = client.get("/api/v1/analyses/999999/status")
    assert response.status_code == 404


def test_status_completed_has_result(client):
    post = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    aid = post.json()["id"]
    data = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert data["status"] == "completed"
    assert data["result"] is not None
    assert "risk_score" in data["result"]
    assert "severity" in data["result"]
    assert "findings" in data["result"]
    assert "suggestions" in data["result"]
    assert "graph_data" in data["result"]


def test_status_completed_result_has_valid_severity(client):
    post = client.post("/api/v1/analyze", json=_wrap(HIGH_RISK_POLICY))
    aid = post.json()["id"]
    data = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert data["result"]["severity"] == "CRITICAL"


def test_status_has_task_id(client):
    post = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    aid = post.json()["id"]
    data = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert "task_id" in data
    assert data["task_id"] == "test-task-sync"


def test_status_pending_has_no_result(test_engine, mock_user):
    """Manually insert a pending record and check status returns null result."""
    from sqlalchemy.orm import sessionmaker
    factory = sessionmaker(bind=test_engine)
    db = factory()
    record = Analysis(
        policy_hash="zz",
        policy_json="{}",
        risk_score=0.0,
        severity="pending",
        findings_json="[]",
        suggestions_json="{}",
        graph_data_json='{"nodes":[],"edges":[]}',
        status="pending",
        task_id="some-task-id",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    analysis_id = record.id
    db.close()

    def override_get_db():
        with Session(test_engine) as s:
            yield s

    with patch("app.db.database.init_db"):
        from app.main import app
        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_current_user] = lambda: mock_user
        with TestClient(app) as c:
            data = c.get(f"/api/v1/analyses/{analysis_id}/status").json()
        app.dependency_overrides.clear()

    assert data["status"] == "pending"
    assert data["result"] is None
