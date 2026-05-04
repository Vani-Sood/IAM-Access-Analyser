"""Unit tests for ReportBuilder — Batch 17."""
from __future__ import annotations

import pytest

from app.analysis.graph_builder import build_graph
from app.ingestion.parser import PolicyDoc


# ── Helpers ───────────────────────────────────────────────────────────────────


def _policy_graph(*statements):
    policy = PolicyDoc.model_validate(
        {"Version": "2012-10-17", "Statement": list(statements)}
    )
    from app.ingestion.expander import expand_wildcards
    return build_graph(expand_wildcards(policy))


def _safe_graph():
    return _policy_graph(
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"},
    )


def _dangerous_graph():
    return _policy_graph(
        {"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"},
    )


MOCK_FINDINGS = [
    {"type": "WILDCARD_ACTION", "severity": "CRITICAL", "message": "iam:* grants full admin"},
]

MOCK_SUGGESTIONS = {
    "least_privilege_policy": {"Version": "2012-10-17", "Statement": []},
    "changes": ["Remove wildcard iam:* action"],
}

ANALYSIS_META = {
    "id": 42,
    "risk_score": 9.5,
    "severity": "CRITICAL",
    "policy_json": '{"Version":"2012-10-17","Statement":[]}',
    "created_at": "2026-04-28T12:00:00+00:00",
}


# ── Import smoke ──────────────────────────────────────────────────────────────


def test_import_report_builder():
    from app.analysis.report import ReportBuilder, ReportData
    assert ReportBuilder is not None
    assert ReportData is not None


def test_report_data_is_dataclass():
    from app.analysis.report import ReportData
    rd = ReportData(
        analysis_id=1,
        generated_at="2026-04-28T12:00:00+00:00",
        risk_score=5.0,
        severity="HIGH",
        findings_count=1,
        privesc_paths_count=0,
        summary={},
        findings=[],
        privesc_paths=[],
        recommendations=[],
    )
    assert rd.analysis_id == 1


# ── ReportBuilder construction ────────────────────────────────────────────────


def test_builder_builds_safe_policy():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    builder = ReportBuilder(
        analysis_id=1,
        graph=g,
        findings=MOCK_FINDINGS,
        suggestions=MOCK_SUGGESTIONS,
        risk_score=2.0,
        severity="LOW",
        created_at="2026-04-28T12:00:00+00:00",
    )
    report = builder.build()
    assert report is not None


def test_builder_returns_report_data():
    from app.analysis.report import ReportBuilder, ReportData
    g = _safe_graph()
    builder = ReportBuilder(
        analysis_id=7,
        graph=g,
        findings=[],
        suggestions={},
        risk_score=1.0,
        severity="LOW",
        created_at="2026-04-28T12:00:00+00:00",
    )
    report = builder.build()
    assert isinstance(report, ReportData)


# ── ReportData fields ─────────────────────────────────────────────────────────


def test_report_analysis_id_matches():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=42, graph=g, findings=[], suggestions={},
        risk_score=1.0, severity="LOW", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert report.analysis_id == 42


def test_report_has_generated_at():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=1.0, severity="LOW", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert isinstance(report.generated_at, str)
    assert len(report.generated_at) > 0


def test_report_risk_score_matches():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert report.risk_score == 9.5


def test_report_severity_matches():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert report.severity == "CRITICAL"


def test_report_findings_count_matches_input():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert report.findings_count == len(MOCK_FINDINGS)


def test_report_findings_list_matches():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert report.findings == MOCK_FINDINGS


def test_report_privesc_paths_populated_for_dangerous_graph():
    from app.analysis.report import ReportBuilder
    g = _dangerous_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert report.privesc_paths_count >= 1
    assert len(report.privesc_paths) >= 1


def test_report_privesc_paths_empty_for_safe_graph():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=1.0, severity="LOW", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert report.privesc_paths_count == 0
    assert report.privesc_paths == []


# ── Summary section ───────────────────────────────────────────────────────────


def test_report_summary_has_required_keys():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=1.0, severity="LOW", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert "total_statements" in report.summary
    assert "total_actions" in report.summary
    assert "dangerous_actions_count" in report.summary
    assert "wildcard_resources_count" in report.summary


def test_report_summary_statement_count():
    from app.analysis.report import ReportBuilder
    g = _dangerous_graph()  # 2 statements
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert report.summary["total_statements"] == 2


def test_report_summary_wildcard_resource_count():
    from app.analysis.report import ReportBuilder
    g = _dangerous_graph()  # Resource: "*"
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert report.summary["wildcard_resources_count"] >= 1


# ── Recommendations ───────────────────────────────────────────────────────────


def test_report_recommendations_is_list():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=1.0, severity="LOW", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert isinstance(report.recommendations, list)


def test_report_dangerous_graph_has_recommendations():
    from app.analysis.report import ReportBuilder
    g = _dangerous_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions=MOCK_SUGGESTIONS,
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    assert len(report.recommendations) >= 1
    for rec in report.recommendations:
        assert isinstance(rec, str)
        assert len(rec) > 0


# ── to_dict ───────────────────────────────────────────────────────────────────


def test_report_data_has_to_dict():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=1.0, severity="LOW", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    d = report.to_dict()
    assert isinstance(d, dict)


def test_report_dict_has_all_top_level_keys():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=1.0, severity="LOW", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    d = report.to_dict()
    required = {
        "analysis_id", "generated_at", "risk_score", "severity",
        "findings_count", "privesc_paths_count", "summary",
        "findings", "privesc_paths", "recommendations",
    }
    assert required.issubset(d.keys())


# ── render_html ───────────────────────────────────────────────────────────────


def test_report_builder_can_render_html():
    from app.analysis.report import ReportBuilder
    g = _dangerous_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions=MOCK_SUGGESTIONS,
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    html = report.render_html()
    assert isinstance(html, str)
    assert "<html" in html or "<!DOCTYPE" in html


def test_report_html_contains_risk_score():
    from app.analysis.report import ReportBuilder
    g = _dangerous_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    html = report.render_html()
    assert "9.5" in html


def test_report_html_contains_severity():
    from app.analysis.report import ReportBuilder
    g = _dangerous_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    html = report.render_html()
    assert "CRITICAL" in html


def test_report_html_contains_privesc_section():
    from app.analysis.report import ReportBuilder
    g = _dangerous_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=MOCK_FINDINGS, suggestions={},
        risk_score=9.5, severity="CRITICAL", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    html = report.render_html()
    assert "privesc" in html.lower() or "privilege escalation" in html.lower()


# ── render_pdf ────────────────────────────────────────────────────────────────


def test_report_builder_can_render_pdf():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=1.0, severity="LOW", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    pdf_bytes = report.render_pdf()
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0


def test_report_pdf_starts_with_pdf_magic():
    from app.analysis.report import ReportBuilder
    g = _safe_graph()
    report = ReportBuilder(
        analysis_id=1, graph=g, findings=[], suggestions={},
        risk_score=1.0, severity="LOW", created_at="2026-04-28T12:00:00+00:00",
    ).build()
    pdf_bytes = report.render_pdf()
    assert pdf_bytes[:4] == b"%PDF"
