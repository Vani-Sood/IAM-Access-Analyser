"""Tests for GET /analyses/{id}/report endpoint — Batch 17."""
from __future__ import annotations

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
        {"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"},
    ],
}

MOCK_LLM = '{"least_privilege_policy": {"Version":"2012-10-17","Statement":[]}, "changes": ["Remove iam:*"]}'


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
        m.id = "test-task-report"
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
    resp = client.post("/api/v1/analyze", json={"mode": "json", "policy": policy})
    assert resp.status_code == 200
    return resp.json()["id"]


# ── Auth ──────────────────────────────────────────────────────────────────────


def test_report_requires_auth():
    with patch("app.db.database.init_db"):
        from app.main import app
        with TestClient(app) as c:
            resp = c.get("/api/v1/analyses/1/report")
    assert resp.status_code == 401


# ── JSON format (default) ─────────────────────────────────────────────────────


def test_report_json_returns_200(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/report")
    assert resp.status_code == 200


def test_report_json_content_type(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/report")
    assert "application/json" in resp.headers["content-type"]


def test_report_json_has_required_fields(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/report").json()
    required = {
        "analysis_id", "generated_at", "risk_score", "severity",
        "findings_count", "privesc_paths_count", "summary",
        "findings", "privesc_paths", "recommendations",
    }
    assert required.issubset(data.keys())


def test_report_json_analysis_id_matches(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/report").json()
    assert data["analysis_id"] == aid


def test_report_json_safe_policy_no_privesc(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/report").json()
    assert data["privesc_paths_count"] == 0
    assert data["privesc_paths"] == []


def test_report_json_dangerous_policy_has_privesc(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/report").json()
    assert data["privesc_paths_count"] >= 1


def test_report_json_recommendations_is_list(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/report").json()
    assert isinstance(data["recommendations"], list)


def test_report_json_summary_has_keys(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/report").json()
    assert "total_statements" in data["summary"]
    assert "total_actions" in data["summary"]


def test_report_json_findings_count_matches_list(client):
    aid = _create_analysis(client, DANGEROUS_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/report").json()
    assert data["findings_count"] == len(data["findings"])


# ── PDF format ────────────────────────────────────────────────────────────────


def test_report_pdf_returns_200(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/report?format=pdf")
    assert resp.status_code == 200


def test_report_pdf_content_type(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/report?format=pdf")
    assert resp.headers["content-type"] == "application/pdf"


def test_report_pdf_content_disposition(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/report?format=pdf")
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert ".pdf" in resp.headers.get("content-disposition", "")


def test_report_pdf_body_is_nonempty(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/report?format=pdf")
    assert len(resp.content) > 0


def test_report_pdf_starts_with_pdf_magic(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/report?format=pdf")
    assert resp.content[:4] == b"%PDF"


# ── Not found ─────────────────────────────────────────────────────────────────


def test_report_unknown_analysis_returns_404(client):
    resp = client.get("/api/v1/analyses/999999/report")
    assert resp.status_code == 404


def test_report_pdf_unknown_analysis_returns_404(client):
    resp = client.get("/api/v1/analyses/999999/report?format=pdf")
    assert resp.status_code == 404


# ── Invalid format ────────────────────────────────────────────────────────────


def test_report_invalid_format_returns_422(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/report?format=xlsx")
    assert resp.status_code == 422
