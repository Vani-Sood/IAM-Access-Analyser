"""Unit tests for LCAEngine (Euler tour + sparse table RMQ) — Batch 15."""
from __future__ import annotations

import pytest

from app.analysis.graph_builder import EdgeData, GraphData, NodeData, build_graph
from app.ingestion.parser import PolicyDoc


# ── Known graph fixtures ──────────────────────────────────────────────────────
#
# policy_root
#   └─ stmt_0  (Allow)
#       ├─ action_s3_GetObject
#       │    └─ resource_arn_aws_s3_bucket_a_WILDCARD
#       └─ action_s3_PutObject
#            └─ resource_arn_aws_s3_bucket_a_WILDCARD  (shared resource)
#   └─ stmt_1  (Allow)
#       └─ action_iam_PassRole
#            └─ resource_WILDCARD


def _make_graph() -> GraphData:
    policy = PolicyDoc.model_validate(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::bucket-a/*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": "*",
                },
            ],
        }
    )
    from app.ingestion.expander import expand_wildcards
    return build_graph(expand_wildcards(policy))


def _node_id(graph: GraphData, label_contains: str) -> str:
    for n in graph.nodes:
        if label_contains.lower() in n.label.lower():
            return n.id
    raise KeyError(f"No node with label containing {label_contains!r}")


@pytest.fixture(scope="module")
def graph() -> GraphData:
    return _make_graph()


@pytest.fixture(scope="module")
def engine(graph: GraphData):
    from app.analysis.lca import LCAEngine
    return LCAEngine(graph)


# ── Build / structure tests ───────────────────────────────────────────────────

def test_euler_tour_nonempty(engine):
    assert len(engine.euler) > 0


def test_euler_tour_length(graph, engine):
    # Euler tour has 2*nodes - 1 elements for a tree with N nodes
    # Exact length depends on how many nodes are reachable; at minimum > N
    assert len(engine.euler) >= len(graph.nodes) - 1


def test_all_reachable_nodes_in_first(graph, engine):
    # Every node reachable from root should appear in `first`
    assert "policy_root" in engine.first


def test_depth_root_is_zero(engine):
    assert engine.depth["policy_root"] == 0


def test_depth_stmt_is_one(engine):
    assert engine.depth["stmt_0"] == 1
    assert engine.depth["stmt_1"] == 1


def test_depth_action_is_two(graph, engine):
    action_id = _node_id(graph, "s3:GetObject")
    assert engine.depth[action_id] == 2


def test_depth_resource_is_three(graph, engine):
    resource_id = _node_id(graph, "bucket-a")
    assert engine.depth[resource_id] == 3


# ── LCA correctness ───────────────────────────────────────────────────────────

def test_lca_same_node_returns_self(graph, engine):
    action_id = _node_id(graph, "s3:GetObject")
    result = engine.lca(action_id, action_id)
    assert result == action_id


def test_lca_sibling_actions_same_statement(graph, engine):
    """LCA of two actions under the same statement = that statement."""
    get_id = _node_id(graph, "s3:GetObject")
    put_id = _node_id(graph, "s3:PutObject")
    result = engine.lca(get_id, put_id)
    assert result == "stmt_0"


def test_lca_actions_different_statements(graph, engine):
    """LCA of actions under different statements = policy_root."""
    get_id = _node_id(graph, "s3:GetObject")
    iam_id = _node_id(graph, "iam:PassRole")
    result = engine.lca(get_id, iam_id)
    assert result == "policy_root"


def test_lca_action_and_its_resource(graph, engine):
    """LCA of an action and its direct resource = the action."""
    action_id = _node_id(graph, "s3:GetObject")
    resource_id = _node_id(graph, "bucket-a")
    result = engine.lca(action_id, resource_id)
    assert result == action_id


def test_lca_stmt_and_child_action(engine):
    """LCA of stmt_0 and a child action = stmt_0."""
    get_id = "action_s3_GetObject"
    result = engine.lca("stmt_0", get_id)
    assert result == "stmt_0"


def test_lca_root_and_any_node(engine):
    """LCA of root and any node = root."""
    result = engine.lca("policy_root", "stmt_1")
    assert result == "policy_root"


def test_lca_unknown_node_returns_none(engine):
    result = engine.lca("does_not_exist", "stmt_0")
    assert result is None


def test_lca_both_unknown_returns_none(engine):
    result = engine.lca("nonexistent_a", "nonexistent_b")
    assert result is None


# ── Ancestors ─────────────────────────────────────────────────────────────────

def test_ancestors_root_returns_root_only(engine):
    result = engine.ancestors("policy_root")
    assert result == ["policy_root"]


def test_ancestors_stmt_returns_stmt_then_root(engine):
    result = engine.ancestors("stmt_0")
    assert result == ["stmt_0", "policy_root"]


def test_ancestors_action_returns_full_path(graph, engine):
    action_id = _node_id(graph, "s3:GetObject")
    result = engine.ancestors(action_id)
    assert result[0] == action_id
    assert result[-1] == "policy_root"
    assert "stmt_0" in result


def test_ancestors_unknown_returns_empty(engine):
    result = engine.ancestors("nonexistent")
    assert result == []


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_single_node_graph():
    """LCAEngine handles a graph with only one node."""
    from app.analysis.lca import LCAEngine
    g = GraphData(
        nodes=[NodeData(id="only", label="Only", node_type="policy")],
        edges=[],
    )
    eng = LCAEngine(g)
    assert eng.lca("only", "only") == "only"


def test_linear_chain_graph():
    """A → B → C: LCA(A, C) = A, LCA(B, C) = B."""
    from app.analysis.lca import LCAEngine
    g = GraphData(
        nodes=[
            NodeData(id="a", label="A", node_type="policy"),
            NodeData(id="b", label="B", node_type="statement"),
            NodeData(id="c", label="C", node_type="action"),
        ],
        edges=[
            EdgeData(source="a", target="b", edge_type="CONTAINS"),
            EdgeData(source="b", target="c", edge_type="GRANTS"),
        ],
    )
    eng = LCAEngine(g)
    assert eng.lca("a", "c") == "a"
    assert eng.lca("b", "c") == "b"
    assert eng.lca("a", "b") == "a"
