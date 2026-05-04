"""Tests for GET /analyses and GET /analyses/{id} endpoints — Batch 10."""
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
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}

MOCK_LLM_RESPONSE = """{
  "least_privilege_policy": {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}]
  },
  "changes": []
}"""


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
        mock_task = MagicMock()
        mock_task.id = "test-task-analyses"
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
    """Wrap a raw policy dict in the new AnalyzeRequest format."""
    return {"mode": "json", "policy": policy}


def test_analyze_now_returns_id(client):
    response = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert isinstance(data["id"], int)
    assert data["id"] > 0


def test_analyze_persists_to_db(client):
    post_resp = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    analysis_id = post_resp.json()["id"]

    get_resp = client.get(f"/api/v1/analyses/{analysis_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == analysis_id


def test_get_analyses_list_returns_200(client):
    response = client.get("/api/v1/analyses")
    assert response.status_code == 200


def test_get_analyses_list_structure(client):
    client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    response = client.get("/api/v1/analyses")
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data


def test_get_analyses_list_has_items(client):
    client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    response = client.get("/api/v1/analyses")
    data = response.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1


def test_get_analyses_list_item_fields(client):
    client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    response = client.get("/api/v1/analyses")
    item = response.json()["items"][0]
    assert "id" in item
    assert "created_at" in item
    assert "risk_score" in item
    assert "severity" in item
    assert "graph_data" not in item


def test_get_analysis_by_id_full_fields(client):
    post_resp = client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    aid = post_resp.json()["id"]

    response = client.get(f"/api/v1/analyses/{aid}")
    data = response.json()
    assert data["id"] == aid
    assert "risk_score" in data
    assert "severity" in data
    assert "findings" in data
    assert "suggestions" in data
    assert "graph_data" in data
    assert "created_at" in data
    assert "policy_json" in data


def test_get_analysis_by_id_not_found(client):
    response = client.get("/api/v1/analyses/999999")
    assert response.status_code == 404


def test_get_analyses_pagination_limit(client):
    for _ in range(3):
        client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    response = client.get("/api/v1/analyses?limit=2&offset=0")
    data = response.json()
    assert len(data["items"]) <= 2
    assert data["limit"] == 2


def test_get_analyses_pagination_offset(client):
    for _ in range(4):
        client.post("/api/v1/analyze", json=_wrap(SIMPLE_POLICY))
    page1 = client.get("/api/v1/analyses?limit=2&offset=0").json()
    page2 = client.get("/api/v1/analyses?limit=2&offset=2").json()
    ids1 = {item["id"] for item in page1["items"]}
    ids2 = {item["id"] for item in page2["items"]}
    assert ids1.isdisjoint(ids2)
