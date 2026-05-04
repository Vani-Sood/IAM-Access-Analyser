"""Unit tests for DashboardBuilder — Batch 22 (TDD RED phase)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import Analysis


# ── Helpers ───────────────────────────────────────────────────────────────────

_SIMPLE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}],
})

_IAM_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["iam:ListRoles", "iam:GetRole"], "Resource": "*"}],
})

_WILD_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
})

_LIVE_POLICY = json.dumps({"role_arn": "arn:aws:iam::123456789012:role/ReadOnly"})


def _make_analysis(
    risk_score: float = 50.0,
    severity: str = "medium",
    days_ago: int = 0,
    policy_json: str | None = None,
) -> Analysis:
    a = Analysis(
        policy_hash="abc",
        policy_json=policy_json if policy_json is not None else _SIMPLE_POLICY,
        risk_score=risk_score,
        severity=severity,
        findings_json="[]",
        suggestions_json="{}",
        graph_data_json='{"nodes":[],"edges":[]}',
        status="completed",
    )
    a.created_at = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return a


# ── Tests: DashboardBuilder ───────────────────────────────────────────────────

def test_empty_analyses_returns_zeros():
    from app.analysis.dashboard import DashboardBuilder
    summary = DashboardBuilder([]).build()
    assert summary.total_analyses == 0
    assert summary.avg_risk_score == 0.0
    assert summary.trend == []
    assert summary.heatmap == []


def test_total_analyses_count():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis() for _ in range(5)]
    summary = DashboardBuilder(analyses).build()
    assert summary.total_analyses == 5


def test_avg_risk_score():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis(risk_score=40.0), _make_analysis(risk_score=60.0)]
    summary = DashboardBuilder(analyses).build()
    assert summary.avg_risk_score == 50.0


def test_avg_risk_score_rounds_to_two_decimals():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis(risk_score=s) for s in [10.0, 20.0, 30.0]]
    summary = DashboardBuilder(analyses).build()
    assert summary.avg_risk_score == round(60.0 / 3, 2)


def test_severity_distribution_counts():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [
        _make_analysis(severity="critical"),
        _make_analysis(severity="critical"),
        _make_analysis(severity="high"),
        _make_analysis(severity="medium"),
        _make_analysis(severity="low"),
        _make_analysis(severity="low"),
        _make_analysis(severity="info"),
    ]
    summary = DashboardBuilder(analyses).build()
    d = summary.severity_distribution
    assert d.critical == 2
    assert d.high == 1
    assert d.medium == 1
    assert d.low == 2
    assert d.info == 1


def test_severity_distribution_zeros_for_missing():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis(severity="high")]
    summary = DashboardBuilder(analyses).build()
    d = summary.severity_distribution
    assert d.critical == 0
    assert d.low == 0
    assert d.info == 0


def test_trend_groups_by_date():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [
        _make_analysis(days_ago=0),
        _make_analysis(days_ago=0),
        _make_analysis(days_ago=1),
    ]
    summary = DashboardBuilder(analyses).build()
    assert len(summary.trend) == 2
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    dates = [t.date for t in summary.trend]
    assert today in dates
    assert yesterday in dates


def test_trend_correct_count_per_day():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis(days_ago=0) for _ in range(3)]
    summary = DashboardBuilder(analyses).build()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    point = next(t for t in summary.trend if t.date == today)
    assert point.count == 3


def test_trend_avg_risk_per_day():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [
        _make_analysis(risk_score=40.0, days_ago=0),
        _make_analysis(risk_score=80.0, days_ago=0),
    ]
    summary = DashboardBuilder(analyses).build()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    point = next(t for t in summary.trend if t.date == today)
    assert point.avg_risk == 60.0


def test_trend_excludes_older_than_30_days():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [
        _make_analysis(days_ago=0),
        _make_analysis(days_ago=31),
    ]
    summary = DashboardBuilder(analyses).build()
    assert len(summary.trend) == 1


def test_trend_sorted_ascending_by_date():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis(days_ago=i) for i in range(5)]
    summary = DashboardBuilder(analyses).build()
    dates = [t.date for t in summary.trend]
    assert dates == sorted(dates)


def test_heatmap_parses_action_pairs():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis(policy_json=_SIMPLE_POLICY)]
    summary = DashboardBuilder(analyses).build()
    services = {e.service for e in summary.heatmap}
    assert "s3" in services


def test_heatmap_counts_occurrences():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis(policy_json=_SIMPLE_POLICY) for _ in range(3)]
    summary = DashboardBuilder(analyses).build()
    entry = next((e for e in summary.heatmap if e.action == "s3:getobject"), None)
    assert entry is not None
    assert entry.count == 3


def test_heatmap_skips_wildcard_action():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis(policy_json=_WILD_POLICY)]
    summary = DashboardBuilder(analyses).build()
    assert all(e.action != "*" for e in summary.heatmap)


def test_heatmap_skips_live_scan_policy():
    from app.analysis.dashboard import DashboardBuilder
    analyses = [_make_analysis(policy_json=_LIVE_POLICY)]
    summary = DashboardBuilder(analyses).build()
    assert summary.heatmap == []


def test_heatmap_max_20_entries():
    from app.analysis.dashboard import DashboardBuilder
    # 25 distinct actions
    actions = [f"svc{i}:Action{i}" for i in range(25)]
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    })
    analyses = [_make_analysis(policy_json=policy)]
    summary = DashboardBuilder(analyses).build()
    assert len(summary.heatmap) <= 20


def test_heatmap_sorted_by_count_descending():
    from app.analysis.dashboard import DashboardBuilder
    policy_s3 = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
    })
    policy_iam = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["iam:ListRoles", "s3:GetObject"], "Resource": "*"}],
    })
    analyses = [_make_analysis(policy_json=policy_s3) for _ in range(3)] + \
               [_make_analysis(policy_json=policy_iam) for _ in range(1)]
    summary = DashboardBuilder(analyses).build()
    counts = [e.count for e in summary.heatmap]
    assert counts == sorted(counts, reverse=True)


def test_heatmap_action_lowercase():
    from app.analysis.dashboard import DashboardBuilder
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["S3:GetObject"], "Resource": "*"}],
    })
    analyses = [_make_analysis(policy_json=policy)]
    summary = DashboardBuilder(analyses).build()
    for e in summary.heatmap:
        assert e.action == e.action.lower()
        assert e.service == e.service.lower()


def test_heatmap_string_action_not_list():
    from app.analysis.dashboard import DashboardBuilder
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}],
    })
    analyses = [_make_analysis(policy_json=policy)]
    summary = DashboardBuilder(analyses).build()
    actions = [e.action for e in summary.heatmap]
    assert "ec2:describeinstances" in actions


def test_org_slug_in_summary():
    from app.analysis.dashboard import DashboardBuilder
    summary = DashboardBuilder([]).build(org_slug="my-org")
    assert summary.org_slug == "my-org"


def test_no_org_slug_is_none():
    from app.analysis.dashboard import DashboardBuilder
    summary = DashboardBuilder([]).build()
    assert summary.org_slug is None


def test_to_dict_has_required_keys():
    from app.analysis.dashboard import DashboardBuilder
    summary = DashboardBuilder([_make_analysis()]).build(org_slug="acme")
    d = summary.to_dict()
    assert "org_slug" in d
    assert "total_analyses" in d
    assert "avg_risk_score" in d
    assert "severity_distribution" in d
    assert "trend" in d
    assert "heatmap" in d


def test_to_dict_severity_distribution_keys():
    from app.analysis.dashboard import DashboardBuilder
    summary = DashboardBuilder([]).build()
    dist = summary.to_dict()["severity_distribution"]
    for key in ("critical", "high", "medium", "low", "info"):
        assert key in dist


def test_to_dict_trend_item_keys():
    from app.analysis.dashboard import DashboardBuilder
    summary = DashboardBuilder([_make_analysis()]).build()
    if summary.trend:
        item = summary.to_dict()["trend"][0]
        assert "date" in item
        assert "count" in item
        assert "avg_risk" in item


def test_to_dict_heatmap_item_keys():
    from app.analysis.dashboard import DashboardBuilder
    summary = DashboardBuilder([_make_analysis()]).build()
    if summary.heatmap:
        item = summary.to_dict()["heatmap"][0]
        assert "service" in item
        assert "action" in item
        assert "count" in item


# ── Tests: rescan_completed_analyses task ─────────────────────────────────────

def test_rescan_task_callable():
    from app.worker.tasks import rescan_completed_analyses
    assert callable(rescan_completed_analyses)


def test_rescan_returns_dict_with_counts(task_engine_b22):
    from app.worker.tasks import _do_rescan
    with __import__("sqlalchemy.orm", fromlist=["Session"]).Session(task_engine_b22) as s:
        result = _do_rescan(s)
    assert isinstance(result, dict)
    assert "scanned" in result
    assert "skipped" in result


def test_rescan_skips_live_scan_analyses(task_engine_b22):
    from app.db.models import Analysis
    from app.worker.tasks import _do_rescan
    from sqlalchemy.orm import Session

    live_policy = json.dumps({"role_arn": "arn:aws:iam::123456789012:role/X"})
    with Session(task_engine_b22) as s:
        a = Analysis(
            policy_hash="live1",
            policy_json=live_policy,
            risk_score=0.0, severity="pending",
            findings_json="[]", suggestions_json="{}",
            graph_data_json='{"nodes":[],"edges":[]}',
            status="completed",
        )
        s.add(a)
        s.commit()
        result = _do_rescan(s)

    assert result["skipped"] >= 1


def test_rescan_processes_json_analyses(task_engine_b22):
    from unittest.mock import patch
    from app.db.models import Analysis
    from app.worker.tasks import _do_rescan
    from sqlalchemy.orm import Session

    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
    })
    with Session(task_engine_b22) as s:
        a = Analysis(
            policy_hash="json_rescan_1",
            policy_json=policy,
            risk_score=0.0, severity="pending",
            findings_json="[]", suggestions_json="{}",
            graph_data_json='{"nodes":[],"edges":[]}',
            status="completed",
        )
        s.add(a)
        s.commit()
        s.refresh(a)

        with patch("app.worker.tasks.run_analysis") as mock_run:
            result = _do_rescan(s)

    assert mock_run.called
    assert result["scanned"] >= 1


@pytest.fixture(scope="module")
def task_engine_b22():
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    from app.db.models import Base
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
