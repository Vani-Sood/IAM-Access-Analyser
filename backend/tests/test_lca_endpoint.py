"""Tests for GET /analyses/{id}/inheritance endpoint — Batch 15."""
from __future__ import annotations

import json
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
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
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
        m.id = "test-task-lca"
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


def _post_and_get_id(client) -> int:
    resp = client.post(
        "/api/v1/analyze",
        json={"mode": "json", "policy": SIMPLE_POLICY},
    )
    assert resp.status_code == 200
    return resp.json()["id"]


def _get_node_id(client, analysis_id: int, label_contains: str) -> str:
    status = client.get(f"/api/v1/analyses/{analysis_id}/status").json()
    nodes = status["result"]["graph_data"]["nodes"]
    for n in nodes:
        if label_contains.lower() in n["label"].lower():
            return n["id"]
    raise ValueError(f"No node with label containing {label_contains!r}")


# ── Basic response shape ──────────────────────────────────────────────────────

def test_inheritance_returns_200(client):
    aid = _post_and_get_id(client)
    get_id = _get_node_id(client, aid, "s3:GetObject")
    put_id = _get_node_id(client, aid, "s3:PutObject")
    resp = client.get(f"/api/v1/analyses/{aid}/inheritance?from_node={get_id}&to_node={put_id}")
    assert resp.status_code == 200


def test_inheritance_has_required_fields(client):
    aid = _post_and_get_id(client)
    get_id = _get_node_id(client, aid, "s3:GetObject")
    put_id = _get_node_id(client, aid, "s3:PutObject")
    data = client.get(f"/api/v1/analyses/{aid}/inheritance?from_node={get_id}&to_node={put_id}").json()
    assert "analysis_id" in data
    assert "from_node" in data
    assert "to_node" in data
    assert "lca_node_id" in data
    assert "lca_node_type" in data
    assert "lca_label" in data


def test_inheritance_sibling_actions_lca_is_statement(client):
    """LCA of two actions under the same statement = that statement."""
    aid = _post_and_get_id(client)
    get_id = _get_node_id(client, aid, "s3:GetObject")
    put_id = _get_node_id(client, aid, "s3:PutObject")
    data = client.get(f"/api/v1/analyses/{aid}/inheritance?from_node={get_id}&to_node={put_id}").json()
    assert data["lca_node_type"] == "statement"
    assert isinstance(data["lca_label"], str) and data["lca_label"]


def test_inheritance_actions_different_stmts_lca_is_policy(client):
    """LCA of actions under different statements = policy root."""
    aid = _post_and_get_id(client)
    get_id = _get_node_id(client, aid, "s3:GetObject")
    iam_id = _get_node_id(client, aid, "iam:PassRole")
    data = client.get(f"/api/v1/analyses/{aid}/inheritance?from_node={get_id}&to_node={iam_id}").json()
    assert data["lca_node_type"] == "policy"


def test_inheritance_same_node_lca_is_self(client):
    aid = _post_and_get_id(client)
    get_id = _get_node_id(client, aid, "s3:GetObject")
    data = client.get(f"/api/v1/analyses/{aid}/inheritance?from_node={get_id}&to_node={get_id}").json()
    assert data["lca_node_id"] == get_id


def test_inheritance_unknown_analysis_returns_404(client):
    resp = client.get("/api/v1/analyses/999999/inheritance?from_node=a&to_node=b")
    assert resp.status_code == 404


def test_inheritance_unknown_node_returns_422(client):
    aid = _post_and_get_id(client)
    resp = client.get(f"/api/v1/analyses/{aid}/inheritance?from_node=does_not_exist&to_node=stmt_0")
    assert resp.status_code == 422


def test_inheritance_missing_param_returns_422(client):
    aid = _post_and_get_id(client)
    resp = client.get(f"/api/v1/analyses/{aid}/inheritance?from_node=stmt_0")
    assert resp.status_code == 422
