"""Integration tests for Neo4j GraphRepository using testcontainers."""
from __future__ import annotations

import pytest

from app.analysis.graph_builder import EdgeData, GraphData, NodeData


def _docker_available() -> bool:
    try:
        import docker
        docker.from_env(timeout=2)
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker socket unavailable — skipping Neo4j testcontainer tests",
)

SIMPLE_GRAPH = GraphData(
    nodes=[
        NodeData(id="policy_root", label="Policy", node_type="policy"),
        NodeData(
            id="stmt_0",
            label="Stmt 0 (Allow)",
            node_type="statement",
            metadata={"effect": "Allow", "statement_idx": 0},
        ),
        NodeData(
            id="action_s3_GetObject",
            label="s3:GetObject",
            node_type="action",
            metadata={"effect": "Allow", "risk_weight": 1.0, "statement_idx": 0},
        ),
        NodeData(
            id="resource_arn_aws_s3_my_bucket_WILDCARD",
            label="arn:aws:s3:::my-bucket/*",
            node_type="resource",
        ),
    ],
    edges=[
        EdgeData(source="policy_root", target="stmt_0", edge_type="CONTAINS"),
        EdgeData(source="stmt_0", target="action_s3_GetObject", edge_type="GRANTS"),
        EdgeData(
            source="action_s3_GetObject",
            target="resource_arn_aws_s3_my_bucket_WILDCARD",
            edge_type="ON_RESOURCE",
        ),
    ],
)


@pytest.fixture(scope="module")
def neo4j_container():
    """Start a real Neo4j container for integration tests."""
    pytest.importorskip("testcontainers")
    from testcontainers.neo4j import Neo4jContainer
    with Neo4jContainer("neo4j:5") as container:
        yield container


@pytest.fixture(scope="module")
def graph_repo(neo4j_container):
    """GraphRepository wired to the test container."""
    from neo4j import GraphDatabase
    from app.graph import neo4j_driver
    from app.graph.neo4j_repository import GraphRepository

    driver = GraphDatabase.driver(
        neo4j_container.get_connection_url(),
        auth=(neo4j_container.username, neo4j_container.password),
    )
    neo4j_driver.set_driver(driver)
    repo = GraphRepository()
    yield repo
    neo4j_driver.close_driver()


def test_store_and_get_graph(graph_repo):
    """Stored graph can be retrieved with correct nodes and edges."""
    analysis_id = "test-analysis-001"
    graph_repo.store_graph(analysis_id, SIMPLE_GRAPH)

    result = graph_repo.get_graph(analysis_id)

    assert result is not None
    node_ids = {n.id for n in result.nodes}
    assert "policy_root" in node_ids
    assert "stmt_0" in node_ids
    assert "action_s3_GetObject" in node_ids

    edge_types = {(e.source, e.target, e.edge_type) for e in result.edges}
    assert ("policy_root", "stmt_0", "CONTAINS") in edge_types
    assert ("stmt_0", "action_s3_GetObject", "GRANTS") in edge_types


def test_store_is_idempotent(graph_repo):
    """Calling store_graph twice does not duplicate nodes/edges."""
    analysis_id = "test-analysis-idem"
    graph_repo.store_graph(analysis_id, SIMPLE_GRAPH)
    graph_repo.store_graph(analysis_id, SIMPLE_GRAPH)

    result = graph_repo.get_graph(analysis_id)
    node_ids = [n.id for n in result.nodes]
    assert node_ids.count("policy_root") == 1


def test_get_graph_returns_none_for_unknown(graph_repo):
    """get_graph returns None when analysis_id not found."""
    result = graph_repo.get_graph("does-not-exist-xyz")
    assert result is None


def test_delete_graph(graph_repo):
    """delete_graph removes all nodes and edges for the analysis."""
    analysis_id = "test-analysis-delete"
    graph_repo.store_graph(analysis_id, SIMPLE_GRAPH)
    graph_repo.delete_graph(analysis_id)

    result = graph_repo.get_graph(analysis_id)
    assert result is None


def test_list_analysis_ids(graph_repo):
    """list_analysis_ids returns all stored IDs."""
    ids = ["test-list-a", "test-list-b", "test-list-c"]
    for aid in ids:
        graph_repo.store_graph(aid, SIMPLE_GRAPH)

    stored = graph_repo.list_analysis_ids()
    for aid in ids:
        assert aid in stored


def test_node_metadata_preserved(graph_repo):
    """Node metadata (effect, risk_weight) round-trips through Neo4j."""
    analysis_id = "test-analysis-meta"
    graph_repo.store_graph(analysis_id, SIMPLE_GRAPH)

    result = graph_repo.get_graph(analysis_id)
    action_node = next(
        n for n in result.nodes if n.id == "action_s3_GetObject"
    )
    assert action_node.metadata.get("effect") == "Allow"
    assert action_node.metadata.get("risk_weight") == pytest.approx(1.0)


def test_store_graph_with_principal_and_trust(graph_repo):
    """Graphs with TRUSTS edges persist and retrieve correctly."""
    trust_graph = GraphData(
        nodes=[
            NodeData(id="policy_root", label="Policy", node_type="policy"),
            NodeData(
                id="principal_arn_aws_iam_123456789_role_MyRole",
                label="AWS:arn:aws:iam::123456789:role/MyRole",
                node_type="principal",
            ),
        ],
        edges=[
            EdgeData(
                source="principal_arn_aws_iam_123456789_role_MyRole",
                target="policy_root",
                edge_type="TRUSTS",
            ),
        ],
    )
    analysis_id = "test-analysis-trust"
    graph_repo.store_graph(analysis_id, trust_graph)

    result = graph_repo.get_graph(analysis_id)
    edge_types = {e.edge_type for e in result.edges}
    assert "TRUSTS" in edge_types
