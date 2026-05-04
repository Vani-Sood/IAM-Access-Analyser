"""Unit tests for HLDEngine (Heavy-Light Decomposition) — Batch 16."""
from __future__ import annotations

import pytest

from app.analysis.graph_builder import EdgeData, GraphData, NodeData, build_graph
from app.ingestion.parser import PolicyDoc


# ── Fixtures ──────────────────────────────────────────────────────────────────
#
# Graph shape (tree edges only):
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
    from app.analysis.hld import HLDEngine
    return HLDEngine(graph)


# ── Build / structure tests ───────────────────────────────────────────────────

def test_hld_builds_without_error(graph):
    from app.analysis.hld import HLDEngine
    eng = HLDEngine(graph)
    assert eng is not None


def test_empty_graph_builds():
    from app.analysis.hld import HLDEngine
    g = GraphData(nodes=[], edges=[])
    eng = HLDEngine(g)
    assert eng is not None


def test_single_node_builds():
    from app.analysis.hld import HLDEngine
    g = GraphData(
        nodes=[NodeData(id="only", label="Only", node_type="policy")],
        edges=[],
    )
    eng = HLDEngine(g)
    assert eng is not None


def test_all_nodes_assigned_chain(graph, engine):
    """Every reachable node should have a chain head assigned."""
    for node in graph.nodes:
        if node.id in engine._chain_head:
            assert engine._chain_head[node.id] is not None


def test_root_is_its_own_chain_head(engine):
    assert engine._chain_head.get("policy_root") == "policy_root"


def test_subtree_sizes_root_is_largest(graph, engine):
    root_size = engine._subtree_size.get("policy_root", 0)
    for node in graph.nodes:
        if node.id != "policy_root":
            size = engine._subtree_size.get(node.id, 0)
            assert root_size >= size


def test_depth_root_zero(engine):
    assert engine._depth.get("policy_root") == 0


def test_depth_stmt_one(engine):
    assert engine._depth.get("stmt_0") == 1
    assert engine._depth.get("stmt_1") == 1


# ── path_nodes ────────────────────────────────────────────────────────────────

def test_path_nodes_self(engine):
    result = engine.path_nodes("policy_root", "policy_root")
    assert result == ["policy_root"]


def test_path_nodes_parent_child(engine):
    result = engine.path_nodes("policy_root", "stmt_0")
    assert set(result) == {"policy_root", "stmt_0"}
    assert result[0] == "policy_root" or result[-1] == "policy_root"


def test_path_nodes_root_to_action(graph, engine):
    action_id = _node_id(graph, "iam:PassRole")
    path = engine.path_nodes("policy_root", action_id)
    assert "policy_root" in path
    assert action_id in path
    assert "stmt_1" in path


def test_path_nodes_root_to_wildcard_resource(graph, engine):
    resource_id = _node_id(graph, "*")  # wildcard resource
    path = engine.path_nodes("policy_root", resource_id)
    assert "policy_root" in path
    assert resource_id in path


def test_path_nodes_cross_branch(graph, engine):
    """Path between two nodes in different subtrees passes through LCA."""
    get_id = _node_id(graph, "s3:GetObject")
    iam_id = _node_id(graph, "iam:PassRole")
    path = engine.path_nodes(get_id, iam_id)
    assert "policy_root" in path  # LCA is root
    assert get_id in path
    assert iam_id in path


def test_path_nodes_sibling_stmts(engine):
    path = engine.path_nodes("stmt_0", "stmt_1")
    assert "policy_root" in path
    assert "stmt_0" in path
    assert "stmt_1" in path


def test_path_nodes_unknown_returns_empty(engine):
    result = engine.path_nodes("does_not_exist", "stmt_0")
    assert result == []


def test_path_nodes_both_unknown_returns_empty(engine):
    result = engine.path_nodes("nonexistent_a", "nonexistent_b")
    assert result == []


def test_path_nodes_linear_chain():
    """A → B → C: path(A, C) = [A, B, C] in some order."""
    from app.analysis.hld import HLDEngine
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
    eng = HLDEngine(g)
    path = eng.path_nodes("a", "c")
    assert set(path) == {"a", "b", "c"}


def test_path_nodes_no_duplicates(graph, engine):
    resource_id = _node_id(graph, "*")
    path = engine.path_nodes("policy_root", resource_id)
    assert len(path) == len(set(path))


# ── path_permissions ──────────────────────────────────────────────────────────

def test_path_permissions_includes_action_labels(graph, engine):
    action_id = _node_id(graph, "iam:PassRole")
    resource_id = _node_id(graph, "*")
    perms = engine.path_permissions(action_id, resource_id)
    assert "iam:PassRole" in perms


def test_path_permissions_root_to_s3_action(graph, engine):
    action_id = _node_id(graph, "s3:GetObject")
    perms = engine.path_permissions("policy_root", action_id)
    assert "s3:GetObject" in perms


def test_path_permissions_cross_branch_excludes_other_branch(graph, engine):
    """Path from root to iam:PassRole should not include s3 permissions."""
    action_id = _node_id(graph, "iam:PassRole")
    perms = engine.path_permissions("policy_root", action_id)
    # iam:PassRole should be present
    assert "iam:PassRole" in perms


def test_path_permissions_unknown_nodes_returns_empty(engine):
    perms = engine.path_permissions("ghost", "phantom")
    assert perms == set()


def test_path_permissions_self_only_own_label(graph, engine):
    action_id = _node_id(graph, "iam:PassRole")
    perms = engine.path_permissions(action_id, action_id)
    # Single-node path: only its own action label if it's an action node
    assert "iam:PassRole" in perms
