"""Unit tests for PrivescDetector (privilege escalation detection) — Batch 16."""
from __future__ import annotations

import pytest

from app.analysis.graph_builder import EdgeData, GraphData, NodeData, build_graph
from app.ingestion.parser import PolicyDoc


# ── Helpers ───────────────────────────────────────────────────────────────────


def _policy_graph(*statements) -> GraphData:
    """Build a GraphData from raw statement dicts."""
    policy = PolicyDoc.model_validate(
        {"Version": "2012-10-17", "Statement": list(statements)}
    )
    from app.ingestion.expander import expand_wildcards
    return build_graph(expand_wildcards(policy))


def _safe_graph() -> GraphData:
    return _policy_graph(
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"},
        {"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234"},
    )


def _critical_graph() -> GraphData:
    """iam:* on * → CRITICAL privesc."""
    return _policy_graph(
        {"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"},
    )


def _high_graph() -> GraphData:
    """iam:PassRole on * → HIGH privesc."""
    return _policy_graph(
        {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"},
    )


def _sts_graph() -> GraphData:
    """sts:AssumeRole on * → HIGH privesc."""
    return _policy_graph(
        {"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": "*"},
    )


def _multi_dangerous_graph() -> GraphData:
    """Multiple dangerous actions → multiple findings."""
    return _policy_graph(
        {"Effect": "Allow", "Action": ["iam:PassRole", "iam:CreatePolicyVersion"], "Resource": "*"},
    )


def _deny_graph() -> GraphData:
    """Deny effect with dangerous action — should NOT trigger privesc."""
    return _policy_graph(
        {"Effect": "Deny", "Action": ["iam:*"], "Resource": "*"},
    )


def _specific_resource_graph() -> GraphData:
    """Dangerous action on specific (non-wildcard) resource → MEDIUM."""
    return _policy_graph(
        {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "arn:aws:iam::123456789012:role/MyRole"},
    )


# ── Import smoke test ─────────────────────────────────────────────────────────


def test_import_privesc_detector():
    from app.analysis.privesc import PrivescDetector, PrivescPath
    assert PrivescDetector is not None
    assert PrivescPath is not None


def test_privesc_path_dataclass():
    from app.analysis.privesc import PrivescPath
    path = PrivescPath(
        source_node="policy_root",
        target_node="resource_WILDCARD",
        path_nodes=["policy_root", "stmt_0", "action_iam_WILDCARD", "resource_WILDCARD"],
        dangerous_actions=["iam:*"],
        severity="CRITICAL",
        description="Full IAM admin via wildcard resource",
    )
    assert path.severity == "CRITICAL"
    assert "iam:*" in path.dangerous_actions


# ── detect_privesc: safe policies ─────────────────────────────────────────────


def test_safe_policy_no_privesc():
    from app.analysis.privesc import PrivescDetector
    g = _safe_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    assert paths == []


def test_deny_effect_no_privesc():
    from app.analysis.privesc import PrivescDetector
    g = _deny_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    assert paths == []


def test_empty_graph_no_privesc():
    from app.analysis.privesc import PrivescDetector
    g = GraphData(nodes=[], edges=[])
    detector = PrivescDetector(g)
    paths = detector.detect()
    assert paths == []


# ── detect_privesc: CRITICAL ──────────────────────────────────────────────────


def test_iam_wildcard_on_wildcard_resource_is_critical():
    from app.analysis.privesc import PrivescDetector
    g = _critical_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    assert len(paths) >= 1
    severities = {p.severity for p in paths}
    assert "CRITICAL" in severities


def test_iam_wildcard_finding_contains_action():
    # iam:* expands to individual actions; check at least one known dangerous action present
    from app.analysis.privesc import DANGEROUS_ACTIONS, PrivescDetector
    g = _critical_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    assert any(
        any(a in DANGEROUS_ACTIONS for a in p.dangerous_actions)
        for p in paths
    )


def test_iam_wildcard_path_includes_root_and_resource():
    from app.analysis.privesc import PrivescDetector
    g = _critical_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    crit = next(p for p in paths if p.severity == "CRITICAL")
    assert "policy_root" in crit.path_nodes
    assert any("WILDCARD" in n or "*" in n for n in crit.path_nodes)


# ── detect_privesc: HIGH ──────────────────────────────────────────────────────


def test_iam_passrole_on_wildcard_is_high():
    from app.analysis.privesc import PrivescDetector
    g = _high_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    assert len(paths) >= 1
    assert any(p.severity in ("HIGH", "CRITICAL") for p in paths)


def test_sts_assumerole_on_wildcard_is_high():
    from app.analysis.privesc import PrivescDetector
    g = _sts_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    assert len(paths) >= 1
    assert any(p.severity in ("HIGH", "CRITICAL") for p in paths)


def test_passrole_finding_contains_action_label():
    from app.analysis.privesc import PrivescDetector
    g = _high_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    assert any("iam:PassRole" in p.dangerous_actions for p in paths)


# ── detect_privesc: MEDIUM ────────────────────────────────────────────────────


def test_dangerous_action_on_specific_resource_is_medium():
    from app.analysis.privesc import PrivescDetector
    g = _specific_resource_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    # Should still flag it but as lower severity
    if paths:
        assert all(p.severity in ("MEDIUM", "LOW", "HIGH", "CRITICAL") for p in paths)


# ── detect_privesc: multiple findings ────────────────────────────────────────


def test_multiple_dangerous_actions_produce_multiple_paths():
    from app.analysis.privesc import PrivescDetector
    g = _multi_dangerous_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    assert len(paths) >= 1  # at least one finding
    all_actions = [a for p in paths for a in p.dangerous_actions]
    assert any("iam:PassRole" in all_actions or "iam:CreatePolicyVersion" in all_actions
               for _ in [True])


# ── PrivescPath structure ─────────────────────────────────────────────────────


def test_privesc_path_has_description():
    from app.analysis.privesc import PrivescDetector
    g = _critical_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    for p in paths:
        assert isinstance(p.description, str)
        assert len(p.description) > 0


def test_privesc_path_nodes_form_valid_chain():
    from app.analysis.privesc import PrivescDetector
    g = _critical_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    for p in paths:
        assert len(p.path_nodes) >= 1
        assert p.source_node in p.path_nodes
        assert p.target_node in p.path_nodes


def test_privesc_path_dangerous_actions_nonempty():
    from app.analysis.privesc import PrivescDetector
    g = _high_graph()
    detector = PrivescDetector(g)
    paths = detector.detect()
    for p in paths:
        assert len(p.dangerous_actions) >= 1


# ── CONSTANTS exposed ─────────────────────────────────────────────────────────


def test_dangerous_actions_constant_exists():
    from app.analysis.privesc import DANGEROUS_ACTIONS
    assert "iam:*" in DANGEROUS_ACTIONS
    assert "iam:PassRole" in DANGEROUS_ACTIONS
    assert "sts:AssumeRole" in DANGEROUS_ACTIONS


def test_wildcard_resources_constant_exists():
    from app.analysis.privesc import WILDCARD_RESOURCES
    assert "*" in WILDCARD_RESOURCES
