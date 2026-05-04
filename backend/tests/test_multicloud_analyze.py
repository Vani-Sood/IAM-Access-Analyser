"""Tests for multi-cloud analyze endpoint — Batch 18."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.api.v1.deps import get_current_user
from app.db.database import get_db

AWS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}
    ],
}

AZURE_POLICY = {
    "Name": "Test Reader",
    "Actions": ["Microsoft.Storage/storageAccounts/read"],
    "NotActions": [],
    "DataActions": [],
    "NotDataActions": [],
    "AssignableScopes": ["/subscriptions/00000000-0000-0000-0000-000000000000"],
}

AZURE_DANGEROUS_POLICY = {
    "Name": "Full Admin",
    "Actions": ["*"],
    "NotActions": [],
    "DataActions": [],
    "NotDataActions": [],
    "AssignableScopes": ["/"],
}

GCP_BINDING_POLICY = {
    "bindings": [
        {"role": "roles/storage.admin", "members": ["user:alice@example.com"]},
    ]
}

GCP_CUSTOM_ROLE = {
    "name": "projects/my-project/roles/myRole",
    "title": "My Role",
    "includedPermissions": ["storage.objects.get", "iam.serviceAccounts.actAs"],
    "stage": "GA",
}

MOCK_LLM = '{"least_privilege_policy": {"Version":"2012-10-17","Statement":[]}, "changes": []}'


def _make_sync_delay(test_engine, mock_llm):
    factory = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)

    def _delay(analysis_id, mode, policy_data, role_arn):
        from app.worker.tasks import run_analysis
        db = factory()
        try:
            with patch("app.ai.llm_client.call_llm", return_value=mock_llm):
                run_analysis(analysis_id, mode, policy_data, role_arn, db_session=db)
            db.commit()
        finally:
            db.close()
        m = MagicMock()
        m.id = "test-task-multicloud"
        return m

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


# ── AWS (default) unchanged ───────────────────────────────────────────────────

def test_aws_analyze_no_cloud_param(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "policy": AWS_POLICY})
    assert resp.status_code == 200


def test_aws_analyze_explicit_cloud_param(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "aws", "policy": AWS_POLICY})
    assert resp.status_code == 200


# ── Azure ─────────────────────────────────────────────────────────────────────

def test_azure_analyze_returns_200(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "azure", "policy": AZURE_POLICY})
    assert resp.status_code == 200


def test_azure_analyze_returns_id_and_status(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "azure", "policy": AZURE_POLICY})
    data = resp.json()
    assert "id" in data
    assert "status" in data


def test_azure_analyze_produces_completed_result(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "azure", "policy": AZURE_POLICY})
    aid = resp.json()["id"]
    status = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert status["status"] == "completed"
    assert status["result"]["risk_score"] >= 0


def test_azure_dangerous_policy_scores_nonzero(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "azure", "policy": AZURE_DANGEROUS_POLICY})
    aid = resp.json()["id"]
    status = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert status["result"]["risk_score"] > 0


def test_azure_analyze_has_graph_data(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "azure", "policy": AZURE_POLICY})
    aid = resp.json()["id"]
    status = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert "graph_data" in status["result"]
    assert len(status["result"]["graph_data"]["nodes"]) > 0


def test_azure_invalid_policy_returns_422(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "azure", "policy": {"Name": "Broken"}})
    assert resp.status_code == 422


def test_azure_empty_actions_returns_422(client):
    bad = {"Name": "Empty", "Actions": [], "NotActions": [], "DataActions": [], "NotDataActions": [], "AssignableScopes": ["/"]}
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "azure", "policy": bad})
    assert resp.status_code == 422


# ── GCP ───────────────────────────────────────────────────────────────────────

def test_gcp_bindings_analyze_returns_200(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "gcp", "policy": GCP_BINDING_POLICY})
    assert resp.status_code == 200


def test_gcp_custom_role_analyze_returns_200(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "gcp", "policy": GCP_CUSTOM_ROLE})
    assert resp.status_code == 200


def test_gcp_analyze_produces_completed_result(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "gcp", "policy": GCP_BINDING_POLICY})
    aid = resp.json()["id"]
    status = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert status["status"] == "completed"
    assert status["result"]["risk_score"] >= 0


def test_gcp_analyze_has_graph_data(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "gcp", "policy": GCP_BINDING_POLICY})
    aid = resp.json()["id"]
    status = client.get(f"/api/v1/analyses/{aid}/status").json()
    assert len(status["result"]["graph_data"]["nodes"]) > 0


def test_gcp_invalid_policy_returns_422(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "gcp", "policy": {"unknown": "value"}})
    assert resp.status_code == 422


def test_gcp_empty_bindings_returns_422(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "gcp", "policy": {"bindings": []}})
    assert resp.status_code == 422


# ── Invalid cloud value ───────────────────────────────────────────────────────

def test_invalid_cloud_value_returns_422(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "alibaba", "policy": AWS_POLICY})
    assert resp.status_code == 422


# ── cloud param in stored record ──────────────────────────────────────────────

def test_azure_result_fetchable_via_analyses_endpoint(client):
    resp = client.post("/api/v1/analyze", json={"mode": "json", "cloud": "azure", "policy": AZURE_POLICY})
    aid = resp.json()["id"]
    detail = client.get(f"/api/v1/analyses/{aid}").json()
    assert detail["id"] == aid
    assert detail["risk_score"] >= 0
