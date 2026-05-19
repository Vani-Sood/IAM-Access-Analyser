"""Tests for POST /analyze endpoint — async Celery task flow (Batch 14)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.api.v1.deps import get_current_user
from app.db.database import get_db

SIMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}

HIGH_RISK_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
    ],
}

MOCK_LLM_RESPONSE = """{
  "least_privilege_policy": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::my-bucket/*"
      }
    ]
  },
  "changes": [
    {
      "original": "s3:PutObject",
      "replacement": [],
      "reason": "Write access not required for read-only use case."
    }
  ]
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
        mock_task.id = "test-task-id-1234"
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
            side_effect=_make_sync_delay(test_engine, MOCK_LLM_RESPONSE),
        ),
    ):
        from app.main import app
        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_current_user] = lambda: mock_user
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.clear()


def _wrap(policy: dict) -> dict:
    return {"mode": "json", "policy": policy}


# ── New async response tests ──────────────────────────────────────────────────

def test_analyze_returns_200(client):
    response = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    assert response.status_code == 200


def test_analyze_response_has_id(client):
    response = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    data = response.json()
    assert "id" in data
    assert isinstance(data["id"], int)
    assert data["id"] > 0


def test_analyze_response_has_task_id(client):
    response = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    data = response.json()
    assert "task_id" in data
    assert data["task_id"] == "test-task-id-1234"


def test_analyze_response_status_pending(client):
    response = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    data = response.json()
    assert data["status"] == "pending"


def test_analyze_response_has_no_risk_score_inline(client):
    """POST response no longer contains risk_score — use status endpoint."""
    response = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    data = response.json()
    assert "risk_score" not in data


# ── Validation (unchanged behavior) ──────────────────────────────────────────

def test_analyze_invalid_json_returns_422(client):
    response = client.post("/api/v1/analyze", json=_wrap({"bad": "schema"}))
    assert response.status_code == 422


def test_analyze_empty_statement_returns_422(client):
    bad_policy = {"Version": "2012-10-17", "Statement": []}
    response = client.post("/api/v1/analyze", json=_wrap(bad_policy))
    assert response.status_code == 422


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# ── Results accessible via status endpoint ────────────────────────────────────

def test_analyze_results_available_via_status(client):
    post = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    aid = post.json()["id"]
    status = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert status["status"] == "completed"
    assert status["result"]["risk_score"] > 0


def test_analyze_high_risk_critical_via_status(client):
    post = client.post("/api/v1/analyze", json=_wrap(HIGH_RISK_POLICY))
    aid = post.json()["id"]
    status = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert status["result"]["severity"] == "CRITICAL"
    assert status["result"]["risk_score"] >= 8.0


def test_analyze_high_risk_findings_via_status(client):
    post = client.post("/api/v1/analyze", json=_wrap(HIGH_RISK_POLICY))
    aid = post.json()["id"]
    status = client.get(f"/api/v1/analyses/{aid}/status").json()
    rule_ids = [f["rule_id"] for f in status["result"]["findings"]]
    assert "IAM_WILDCARD" in rule_ids


def test_analyze_graph_data_via_status(client):
    post = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    aid = post.json()["id"]
    status = client.get(f"/api/v1/analyses/{aid}/status").json()
    gd = status["result"]["graph_data"]
    assert "nodes" in gd and "edges" in gd
    node_types = {n["node_type"] for n in gd["nodes"]}
    assert "policy" in node_types
    assert "action" in node_types


def test_analyze_graph_edges_required_fields_via_status(client):
    post = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    aid = post.json()["id"]
    edges = client.get(f"/api/v1/analyses/{aid}/status").json()["result"]["graph_data"]["edges"]
    for edge in edges:
        assert "source" in edge
        assert "target" in edge
        assert "edge_type" in edge


def test_analyze_suggestions_via_status(client):
    post = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    aid = post.json()["id"]
    suggestions = client.get(f"/api/v1/analyses/{aid}/status").json()["result"]["suggestions"]
    assert "least_privilege_policy" in suggestions or "error" in suggestions


def test_analyze_findings_structure_via_status(client):
    post = client.post("/api/v1/analyze", json=_wrap(HIGH_RISK_POLICY))
    aid = post.json()["id"]
    findings = client.get(f"/api/v1/analyses/{aid}/status").json()["result"]["findings"]
    if findings:
        f = findings[0]
        assert "rule_id" in f
        assert "severity" in f
        assert "message" in f
        assert "statement_idx" in f
