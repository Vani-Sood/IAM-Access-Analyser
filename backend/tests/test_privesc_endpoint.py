"""Tests for GET /analyses/{id}/privesc endpoint — Batch 16."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.api.v1.deps import get_current_user
from app.db.database import get_db

SAFE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}

DANGEROUS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["iam:*"],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": ["iam:PassRole"],
            "Resource": "*",
        },
    ],
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
        m.id = "test-task-privesc"
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


def _create_analysis(client, policy: dict) -> int:
    resp = client.post(
        "/api/v1/analyze",
        json={"mode": "json", "policy": policy},
    )
    assert resp.status_code == 200
    return resp.json()["id"]


# ── Auth ──────────────────────────────────────────────────────────────────────


def test_privesc_requires_auth():
    with patch("app.db.database.init_db"):
        from app.main import app
        with TestClient(app) as c:
            resp = c.get("/api/v1/analyses/1/privesc")
    assert resp.status_code == 401


# ── Basic response shape ──────────────────────────────────────────────────────


def test_privesc_returns_200(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/privesc")
    assert resp.status_code == 200


def test_privesc_has_required_fields(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    assert "analysis_id" in data
    assert "paths" in data
    assert "total_paths" in data


def test_privesc_paths_is_list(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    assert isinstance(data["paths"], list)


def test_privesc_total_paths_matches_list_length(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    assert data["total_paths"] == len(data["paths"])


# ── Not found ─────────────────────────────────────────────────────────────────


def test_privesc_unknown_analysis_returns_404(client):
    resp = client.get("/api/v1/analyses/999999/privesc")
    assert resp.status_code == 404


# ── Safe policy → no findings ─────────────────────────────────────────────────


def test_privesc_safe_policy_no_paths(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    assert data["total_paths"] == 0
    assert data["paths"] == []


# ── Dangerous policy → findings ───────────────────────────────────────────────


def test_privesc_dangerous_policy_has_paths(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    assert data["total_paths"] >= 1


def test_privesc_path_items_have_required_fields(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    for path in data["paths"]:
        assert "source_node" in path
        assert "target_node" in path
        assert "path_nodes" in path
        assert "dangerous_actions" in path
        assert "severity" in path
        assert "description" in path


def test_privesc_severity_is_valid(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    for path in data["paths"]:
        assert path["severity"] in valid_severities


def test_privesc_iam_wildcard_is_critical(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    critical_paths = [p for p in data["paths"] if p["severity"] == "CRITICAL"]
    assert len(critical_paths) >= 1


def test_privesc_dangerous_actions_nonempty(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    for path in data["paths"]:
        assert len(path["dangerous_actions"]) >= 1


def test_privesc_path_nodes_is_list(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    for path in data["paths"]:
        assert isinstance(path["path_nodes"], list)
        assert len(path["path_nodes"]) >= 1


def test_privesc_description_is_nonempty_string(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    for path in data["paths"]:
        assert isinstance(path["description"], str)
        assert len(path["description"]) > 0


# ── analysis_id in response ───────────────────────────────────────────────────


def test_privesc_analysis_id_matches(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/privesc").json()
    assert data["analysis_id"] == aid
