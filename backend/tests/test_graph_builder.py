from __future__ import annotations

import pytest

from app.ingestion.parser import PolicyDoc

SIMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}

WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
    ],
}

DENY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": "*"}
    ],
}

MULTI_STATEMENT_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::bucket-a/*",
        },
        {
            "Effect": "Allow",
            "Action": ["ec2:DescribeInstances"],
            "Resource": "*",
        },
    ],
}


def test_build_graph_returns_graph_data():
    from app.analysis.graph_builder import GraphData, build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    result = build_graph(policy)
    assert isinstance(result, GraphData)


def test_build_graph_has_policy_node():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    types = [n.node_type for n in graph.nodes]
    assert "policy" in types


def test_build_graph_policy_node_count_is_one():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    policy_nodes = [n for n in graph.nodes if n.node_type == "policy"]
    assert len(policy_nodes) == 1


def test_build_graph_has_action_nodes():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    labels = {n.label for n in graph.nodes if n.node_type == "action"}
    assert "s3:GetObject" in labels
    assert "s3:PutObject" in labels


def test_build_graph_has_resource_nodes():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    resource_nodes = [n for n in graph.nodes if n.node_type == "resource"]
    assert len(resource_nodes) >= 1


def test_build_graph_resource_node_label_matches():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    labels = {n.label for n in graph.nodes if n.node_type == "resource"}
    assert "arn:aws:s3:::my-bucket/*" in labels


def test_build_graph_has_edges():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    assert len(graph.edges) > 0


def test_build_graph_node_ids_unique():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    ids = [n.id for n in graph.nodes]
    assert len(ids) == len(set(ids))


def test_build_graph_edges_unique():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    keys = [(e.source, e.target, e.edge_type) for e in graph.edges]
    assert len(keys) == len(set(keys))


def test_build_graph_policy_contains_statement_edges():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    policy_node = next(n for n in graph.nodes if n.node_type == "policy")
    contains_edges = [e for e in graph.edges if e.source == policy_node.id and e.edge_type == "CONTAINS"]
    assert len(contains_edges) == 1  # one statement


def test_build_graph_action_on_resource_edges():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    action_ids = {n.id for n in graph.nodes if n.node_type == "action"}
    resource_ids = {n.id for n in graph.nodes if n.node_type == "resource"}
    on_resource = [
        e for e in graph.edges
        if e.source in action_ids and e.target in resource_ids
    ]
    assert len(on_resource) > 0


def test_build_graph_deny_actions_included():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(DENY_POLICY)
    graph = build_graph(policy)
    labels = {n.label for n in graph.nodes if n.node_type == "action"}
    assert "s3:DeleteObject" in labels


def test_build_graph_wildcard_resource_node():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(WILDCARD_POLICY)
    graph = build_graph(policy)
    labels = {n.label for n in graph.nodes if n.node_type == "resource"}
    assert "*" in labels


def test_build_graph_multi_statement_all_actions():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(MULTI_STATEMENT_POLICY)
    graph = build_graph(policy)
    labels = {n.label for n in graph.nodes if n.node_type == "action"}
    assert "s3:GetObject" in labels
    assert "ec2:DescribeInstances" in labels


def test_build_graph_multi_statement_all_resources():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(MULTI_STATEMENT_POLICY)
    graph = build_graph(policy)
    labels = {n.label for n in graph.nodes if n.node_type == "resource"}
    assert "arn:aws:s3:::bucket-a/*" in labels
    assert "*" in labels


def test_build_graph_action_node_has_effect_metadata():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    action_node = next(n for n in graph.nodes if n.node_type == "action")
    assert "effect" in action_node.metadata
    assert action_node.metadata["effect"] == "Allow"


def test_build_graph_deny_action_effect_metadata():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(DENY_POLICY)
    graph = build_graph(policy)
    action_node = next(n for n in graph.nodes if n.node_type == "action")
    assert action_node.metadata["effect"] == "Deny"


def test_graph_data_serializable():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    data = graph.to_dict()
    assert "nodes" in data
    assert "edges" in data
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)
    assert all("id" in n and "label" in n and "node_type" in n for n in data["nodes"])
    assert all("source" in e and "target" in e and "edge_type" in e for e in data["edges"])


# ── Batch 9: Statement nodes ──────────────────────────────────────────

def test_build_graph_has_statement_nodes():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    stmt_nodes = [n for n in graph.nodes if n.node_type == "statement"]
    assert len(stmt_nodes) == 1


def test_build_graph_multi_statement_node_count():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(MULTI_STATEMENT_POLICY)
    graph = build_graph(policy)
    stmt_nodes = [n for n in graph.nodes if n.node_type == "statement"]
    assert len(stmt_nodes) == 2


def test_statement_node_has_effect_metadata():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    stmt_node = next(n for n in graph.nodes if n.node_type == "statement")
    assert "effect" in stmt_node.metadata
    assert stmt_node.metadata["effect"] == "Allow"


def test_statement_node_has_idx_metadata():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    stmt_node = next(n for n in graph.nodes if n.node_type == "statement")
    assert "statement_idx" in stmt_node.metadata
    assert stmt_node.metadata["statement_idx"] == 0


def test_statement_grants_action_edges():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    stmt_node = next(n for n in graph.nodes if n.node_type == "statement")
    grants = [e for e in graph.edges if e.source == stmt_node.id and e.edge_type == "GRANTS"]
    assert len(grants) == 2  # s3:GetObject, s3:PutObject


def test_multi_statement_each_grants_own_actions():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(MULTI_STATEMENT_POLICY)
    graph = build_graph(policy)
    stmt_nodes = sorted(
        [n for n in graph.nodes if n.node_type == "statement"],
        key=lambda n: n.metadata["statement_idx"],
    )
    # stmt 0 grants s3:GetObject, stmt 1 grants ec2:DescribeInstances
    stmt0_grants = {
        e.target for e in graph.edges
        if e.source == stmt_nodes[0].id and e.edge_type == "GRANTS"
    }
    stmt1_grants = {
        e.target for e in graph.edges
        if e.source == stmt_nodes[1].id and e.edge_type == "GRANTS"
    }
    assert len(stmt0_grants) == 1
    assert len(stmt1_grants) == 1
    assert stmt0_grants != stmt1_grants


def test_deny_statement_node_effect():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(DENY_POLICY)
    graph = build_graph(policy)
    stmt_node = next(n for n in graph.nodes if n.node_type == "statement")
    assert stmt_node.metadata["effect"] == "Deny"


# ── Batch 9: risk_weight + statement_idx on action nodes ─────────────

def test_action_node_has_risk_weight():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    action_nodes = [n for n in graph.nodes if n.node_type == "action"]
    for node in action_nodes:
        assert "risk_weight" in node.metadata


def test_dangerous_action_has_correct_risk_weight():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(WILDCARD_POLICY)  # iam:*
    graph = build_graph(policy)
    action_node = next(n for n in graph.nodes if n.label == "iam:*")
    assert action_node.metadata["risk_weight"] == 10.0


def test_default_action_risk_weight_is_one():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)  # s3:GetObject not in weights
    graph = build_graph(policy)
    action_node = next(n for n in graph.nodes if n.label == "s3:GetObject")
    assert action_node.metadata["risk_weight"] == 1.0


def test_action_node_has_statement_idx():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(SIMPLE_POLICY)
    graph = build_graph(policy)
    action_nodes = [n for n in graph.nodes if n.node_type == "action"]
    for node in action_nodes:
        assert "statement_idx" in node.metadata


def test_multi_statement_action_idx_correct():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(MULTI_STATEMENT_POLICY)
    graph = build_graph(policy)
    s3_node = next(n for n in graph.nodes if n.label == "s3:GetObject")
    ec2_node = next(n for n in graph.nodes if n.label == "ec2:DescribeInstances")
    assert s3_node.metadata["statement_idx"] == 0
    assert ec2_node.metadata["statement_idx"] == 1


# ── Batch 9: Principal nodes ──────────────────────────────────────────

PRINCIPAL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "sts:AssumeRole",
            "Resource": "*",
        }
    ],
}

NO_PRINCIPAL_POLICY = SIMPLE_POLICY


def test_principal_node_created_when_present():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(PRINCIPAL_POLICY)
    graph = build_graph(policy)
    principal_nodes = [n for n in graph.nodes if n.node_type == "principal"]
    assert len(principal_nodes) == 1


def test_no_principal_node_without_principal():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(NO_PRINCIPAL_POLICY)
    graph = build_graph(policy)
    principal_nodes = [n for n in graph.nodes if n.node_type == "principal"]
    assert len(principal_nodes) == 0


def test_principal_node_has_trusts_edge():
    from app.analysis.graph_builder import build_graph

    policy = PolicyDoc.model_validate(PRINCIPAL_POLICY)
    graph = build_graph(policy)
    principal_node = next(n for n in graph.nodes if n.node_type == "principal")
    trusts_edges = [e for e in graph.edges if e.source == principal_node.id and e.edge_type == "TRUSTS"]
    assert len(trusts_edges) == 1
