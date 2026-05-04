"""Tests for GET /analyses/{id}/compliance — Batch 19 (TDD RED phase)."""
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
    ],
}

MOCK_LLM = (
    '{"least_privilege_policy": {"Version":"2012-10-17","Statement":[]}, '
    '"changes": ["Remove iam:*"]}'
)


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
        m.id = "test-task-compliance"
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


def test_compliance_requires_auth():
    with patch("app.db.database.init_db"):
        from app.main import app

        with TestClient(app) as c:
            resp = c.get("/api/v1/analyses/1/compliance?framework=cis")
    assert resp.status_code == 401


# ── Framework parameter ───────────────────────────────────────────────────────


def test_compliance_cis_returns_200(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis")
    assert resp.status_code == 200


def test_compliance_nist_returns_200(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=nist")
    assert resp.status_code == 200


def test_compliance_soc2_returns_200(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=soc2")
    assert resp.status_code == 200


def test_compliance_unknown_framework_returns_422(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=invalid")
    assert resp.status_code == 422


def test_compliance_missing_framework_returns_422(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance")
    assert resp.status_code == 422


def test_compliance_unknown_analysis_returns_404(client):
    resp = client.get("/api/v1/analyses/999999/compliance?framework=cis")
    assert resp.status_code == 404


# ── JSON response shape ───────────────────────────────────────────────────────


def test_compliance_json_content_type(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis")
    assert "application/json" in resp.headers["content-type"]


def test_compliance_json_has_required_fields(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis").json()
    for key in ("analysis_id", "framework", "generated_at", "controls",
                "passed", "failed", "warnings", "not_applicable", "score"):
        assert key in data, f"missing key: {key}"


def test_compliance_json_analysis_id_matches(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/compliance?framework=nist").json()
    assert data["analysis_id"] == aid


def test_compliance_json_framework_matches(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/compliance?framework=soc2").json()
    assert data["framework"] == "soc2"


def test_compliance_json_controls_is_list(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis").json()
    assert isinstance(data["controls"], list)


def test_compliance_json_controls_not_empty(client):
    aid = _create_analysis(client, SAFE_POLICY)
    data = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis").json()
    assert len(data["controls"]) > 0


def test_compliance_json_score_in_range(client):
    aid = _create_analysis(client, SAFE_POLICY)
    score = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis").json()["score"]
    assert 0.0 <= score <= 100.0


def test_compliance_dangerous_policy_lower_score(client):
    safe_id = _create_analysis(client, SAFE_POLICY)
    danger_id = _create_analysis(client, DANGEROUS_POLICY)
    safe_score = client.get(f"/api/v1/analyses/{safe_id}/compliance?framework=cis").json()["score"]
    danger_score = client.get(f"/api/v1/analyses/{danger_id}/compliance?framework=cis").json()["score"]
    assert danger_score <= safe_score


def test_compliance_count_consistency(client):
    aid = _create_analysis(client, SAFE_POLICY)
    d = client.get(f"/api/v1/analyses/{aid}/compliance?framework=nist").json()
    controls = d["controls"]
    assert d["passed"] == sum(1 for c in controls if c["status"] == "PASS")
    assert d["failed"] == sum(1 for c in controls if c["status"] == "FAIL")
    assert d["warnings"] == sum(1 for c in controls if c["status"] == "WARNING")
    assert d["not_applicable"] == sum(1 for c in controls if c["status"] == "NOT_APPLICABLE")


# ── XLSX export ───────────────────────────────────────────────────────────────


def test_compliance_xlsx_returns_200(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis&format=xlsx")
    assert resp.status_code == 200


def test_compliance_xlsx_content_type(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis&format=xlsx")
    assert "spreadsheetml" in resp.headers["content-type"]


def test_compliance_xlsx_content_disposition(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis&format=xlsx")
    cd = resp.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert ".xlsx" in cd


def test_compliance_xlsx_body_nonempty(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis&format=xlsx")
    assert len(resp.content) > 0


def test_compliance_xlsx_valid_zip_magic(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=nist&format=xlsx")
    assert resp.content[:2] == b"PK"


def test_compliance_xlsx_invalid_format_returns_422(client):
    aid = _create_analysis(client, SAFE_POLICY)
    resp = client.get(f"/api/v1/analyses/{aid}/compliance?framework=cis&format=pdf")
    assert resp.status_code == 422


def test_compliance_xlsx_unknown_analysis_returns_404(client):
    resp = client.get("/api/v1/analyses/999999/compliance?framework=cis&format=xlsx")
    assert resp.status_code == 404
