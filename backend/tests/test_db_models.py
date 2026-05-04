"""Tests for SQLAlchemy Analysis model — Batch 10."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from app.db.models import Analysis


@pytest.fixture()
def session(test_engine):
    with Session(test_engine) as s:
        yield s
        s.rollback()


def test_analysis_table_exists(test_engine):
    with test_engine.connect() as conn:
        names = test_engine.dialect.get_table_names(conn)
    assert "analyses" in names


def test_analysis_create_and_retrieve(session):
    record = Analysis(
        policy_hash="abc123",
        policy_json='{"Version":"2012-10-17","Statement":[]}',
        risk_score=7.5,
        severity="HIGH",
        findings_json="[]",
        suggestions_json="{}",
        graph_data_json="{}",
    )
    session.add(record)
    session.flush()

    fetched = session.get(Analysis, record.id)
    assert fetched is not None
    assert fetched.risk_score == 7.5
    assert fetched.severity == "HIGH"
    assert fetched.policy_hash == "abc123"


def test_analysis_id_autoincrement(session):
    r1 = Analysis(
        policy_hash="h1",
        policy_json="{}",
        risk_score=1.0,
        severity="LOW",
        findings_json="[]",
        suggestions_json="{}",
        graph_data_json="{}",
    )
    r2 = Analysis(
        policy_hash="h2",
        policy_json="{}",
        risk_score=2.0,
        severity="LOW",
        findings_json="[]",
        suggestions_json="{}",
        graph_data_json="{}",
    )
    session.add_all([r1, r2])
    session.flush()
    assert r2.id > r1.id


def test_analysis_created_at_auto(session):
    before = datetime.now(timezone.utc)
    record = Analysis(
        policy_hash="ts_test",
        policy_json="{}",
        risk_score=0.0,
        severity="LOW",
        findings_json="[]",
        suggestions_json="{}",
        graph_data_json="{}",
    )
    session.add(record)
    session.flush()
    after = datetime.now(timezone.utc)

    assert record.created_at is not None
    ts = record.created_at.replace(tzinfo=timezone.utc) if record.created_at.tzinfo is None else record.created_at
    # truncate to seconds — SQLite server_default has no microseconds
    before_s = before.replace(microsecond=0)
    after_s = after.replace(microsecond=0) + timedelta(seconds=1)
    assert before_s <= ts <= after_s


def test_analysis_json_fields_roundtrip(session):
    findings = [{"rule_id": "IAM_WILDCARD", "severity": "CRITICAL", "message": "test", "statement_idx": 0}]
    suggestions = {"least_privilege_policy": None, "changes": []}
    graph = {"nodes": [], "edges": []}

    record = Analysis(
        policy_hash="json_test",
        policy_json=json.dumps({"Version": "2012-10-17"}),
        risk_score=5.0,
        severity="MEDIUM",
        findings_json=json.dumps(findings),
        suggestions_json=json.dumps(suggestions),
        graph_data_json=json.dumps(graph),
    )
    session.add(record)
    session.flush()

    fetched = session.get(Analysis, record.id)
    assert json.loads(fetched.findings_json) == findings
    assert json.loads(fetched.suggestions_json) == suggestions
    assert json.loads(fetched.graph_data_json) == graph
