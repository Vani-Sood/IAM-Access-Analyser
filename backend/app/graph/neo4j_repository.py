"""Neo4j repository for IAM permission graph persistence."""
from __future__ import annotations

import json

from app.analysis.graph_builder import EdgeData, GraphData, NodeData
from app.graph.neo4j_driver import get_session


class GraphRepository:
    """Store and retrieve IAM permission graphs in Neo4j."""

    def store_graph(self, analysis_id: str, graph: GraphData) -> None:
        """Persist graph nodes and edges for an analysis. Idempotent (MERGE)."""
        with get_session() as session:
            # Nodes
            for node in graph.nodes:
                session.run(
                    """
                    MERGE (n:IamNode {analysis_id: $analysis_id, node_id: $node_id})
                    SET n.label = $label,
                        n.node_type = $node_type,
                        n.metadata_json = $metadata_json
                    """,
                    analysis_id=analysis_id,
                    node_id=node.id,
                    label=node.label,
                    node_type=node.node_type,
                    metadata_json=json.dumps(node.metadata),
                )
            # Edges
            for edge in graph.edges:
                session.run(
                    """
                    MATCH
                        (src:IamNode {analysis_id: $analysis_id, node_id: $src_id}),
                        (tgt:IamNode {analysis_id: $analysis_id, node_id: $tgt_id})
                    MERGE (src)-[r:IAM_EDGE {
                        analysis_id: $analysis_id,
                        edge_type: $edge_type
                    }]->(tgt)
                    """,
                    analysis_id=analysis_id,
                    src_id=edge.source,
                    tgt_id=edge.target,
                    edge_type=edge.edge_type,
                )

    def get_graph(self, analysis_id: str) -> GraphData | None:
        """Return GraphData for an analysis, or None if not found."""
        with get_session() as session:
            node_records = session.run(
                """
                MATCH (n:IamNode {analysis_id: $analysis_id})
                RETURN n.node_id AS node_id,
                       n.label AS label,
                       n.node_type AS node_type,
                       n.metadata_json AS metadata_json
                """,
                analysis_id=analysis_id,
            ).data()

            if not node_records:
                return None

            edge_records = session.run(
                """
                MATCH (src:IamNode {analysis_id: $analysis_id})
                      -[r:IAM_EDGE {analysis_id: $analysis_id}]->
                      (tgt:IamNode {analysis_id: $analysis_id})
                RETURN src.node_id AS source,
                       tgt.node_id AS target,
                       r.edge_type AS edge_type
                """,
                analysis_id=analysis_id,
            ).data()

        nodes = [
            NodeData(
                id=rec["node_id"],
                label=rec["label"],
                node_type=rec["node_type"],
                metadata=json.loads(rec["metadata_json"] or "{}"),
            )
            for rec in node_records
        ]
        edges = [
            EdgeData(
                source=rec["source"],
                target=rec["target"],
                edge_type=rec["edge_type"],
            )
            for rec in edge_records
        ]
        return GraphData(nodes=nodes, edges=edges)

    def delete_graph(self, analysis_id: str) -> None:
        """Remove all nodes and edges for an analysis."""
        with get_session() as session:
            session.run(
                """
                MATCH (n:IamNode {analysis_id: $analysis_id})
                DETACH DELETE n
                """,
                analysis_id=analysis_id,
            )

    def list_analysis_ids(self) -> list[str]:
        """Return all distinct analysis IDs stored in Neo4j."""
        with get_session() as session:
            records = session.run(
                """
                MATCH (n:IamNode)
                RETURN DISTINCT n.analysis_id AS analysis_id
                """
            ).data()
        return [rec["analysis_id"] for rec in records]
