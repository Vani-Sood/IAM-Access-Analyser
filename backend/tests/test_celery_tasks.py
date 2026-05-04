"""Unit tests for run_analysis() Celery task logic — Batch 14."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import Analysis, Base

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

HIGH_RISK_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
}

MOCK_LLM = """{
  "least_privilege_policy": {"Version": "2012-10-17", "Statement": []},
  "changes": []
}"""


@pytest.fixture(scope="module")
def task_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture
def task_db(task_engine):
    session = Session(task_engine)
    yield session
    session.close()


@pytest.fixture
def pending_record(task_db):
    """Create a pending Analysis record for task tests."""
    record = Analysis(
        policy_hash="abc123",
        policy_json="{}",
        risk_score=0.0,
        severity="pending",
        findings_json="[]",
        suggestions_json="{}",
        graph_data_json='{"nodes":[],"edges":[]}',
        status="pending",
    )
    task_db.add(record)
    task_db.commit()
    task_db.refresh(record)
    return record


def test_run_analysis_sets_status_completed(pending_record, task_db):
    from app.worker.tasks import run_analysis
    with patch("app.ai.llm_client.call_llm", return_value=MOCK_LLM):
        run_analysis(pending_record.id, "json", SIMPLE_POLICY, None, db_session=task_db)

    task_db.refresh(pending_record)
    assert pending_record.status == "completed"


def test_run_analysis_updates_risk_score(pending_record, task_db):
    from app.worker.tasks import run_analysis
    with patch("app.ai.llm_client.call_llm", return_value=MOCK_LLM):
        run_analysis(pending_record.id, "json", SIMPLE_POLICY, None, db_session=task_db)

    task_db.refresh(pending_record)
    assert pending_record.risk_score > 0.0


def test_run_analysis_updates_severity(pending_record, task_db):
    from app.worker.tasks import run_analysis
    with patch("app.ai.llm_client.call_llm", return_value=MOCK_LLM):
        run_analysis(pending_record.id, "json", HIGH_RISK_POLICY, None, db_session=task_db)

    task_db.refresh(pending_record)
    assert pending_record.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_run_analysis_populates_findings(pending_record, task_db):
    import json
    from app.worker.tasks import run_analysis
    with patch("app.ai.llm_client.call_llm", return_value=MOCK_LLM):
        run_analysis(pending_record.id, "json", HIGH_RISK_POLICY, None, db_session=task_db)

    task_db.refresh(pending_record)
    findings = json.loads(pending_record.findings_json)
    assert isinstance(findings, list)


def test_run_analysis_populates_graph_data(pending_record, task_db):
    import json
    from app.worker.tasks import run_analysis
    with patch("app.ai.llm_client.call_llm", return_value=MOCK_LLM):
        run_analysis(pending_record.id, "json", SIMPLE_POLICY, None, db_session=task_db)

    task_db.refresh(pending_record)
    gd = json.loads(pending_record.graph_data_json)
    assert "nodes" in gd and len(gd["nodes"]) > 0


def test_run_analysis_sets_failed_on_bad_mode(pending_record, task_db):
    from app.worker.tasks import run_analysis
    run_analysis(pending_record.id, "unknown_mode", None, None, db_session=task_db)

    task_db.refresh(pending_record)
    assert pending_record.status == "failed"


def test_analyze_policy_task_callable():
    """Task is registered and callable via .apply()."""
    from app.worker.tasks import analyze_policy_task
    assert callable(analyze_policy_task)
