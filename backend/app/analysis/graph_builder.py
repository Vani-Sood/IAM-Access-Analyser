from __future__ import annotations

import json
from dataclasses import dataclass, field

import networkx as nx

from app.ingestion.parser import PolicyDoc

# Imported here to avoid circular deps — same weights as risk_scorer
_RISK_WEIGHTS: dict[str, float] = {
    "iam:*":                           10.0,
    "*":                               10.0,
    "iam:PassRole":                     9.5,
    "iam:CreatePolicyVersion":          9.0,
    "iam:AttachRolePolicy":             9.0,
    "iam:PutRolePolicy":                9.0,
    "sts:AssumeRole":                   8.5,
    "secretsmanager:GetSecretValue":    8.0,
    "kms:Decrypt":                      7.5,
    "ec2:*":                            7.0,
    "cloudformation:*":                 7.0,
    "s3:*":                             6.5,
    "lambda:InvokeFunction":            6.0,
}
_DEFAULT_RISK_WEIGHT: float = 1.0


@dataclass
class NodeData:
    id: str
    label: str
    node_type: str  # "policy" | "statement" | "action" | "resource" | "principal"
    metadata: dict = field(default_factory=dict)


@dataclass
class EdgeData:
    source: str
    target: str
    edge_type: str  # "CONTAINS" | "GRANTS" | "ON_RESOURCE" | "TRUSTS"


@dataclass
class GraphData:
    nodes: list[NodeData]
    edges: list[EdgeData]

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "node_type": n.node_type,
                    "metadata": n.metadata,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "edge_type": e.edge_type,
                }
                for e in self.edges
            ],
        }


def _safe_id(prefix: str, raw: str) -> str:
    sanitized = (
        raw.replace(":", "_")
           .replace("/", "_")
           .replace("*", "WILDCARD")
           .replace("-", "_")
           .replace(" ", "_")
    )
    return f"{prefix}_{sanitized}"


def _principal_label(principal: str | dict | list) -> str:
    if isinstance(principal, str):
        return principal
    if isinstance(principal, dict):
        parts = []
        for k, v in principal.items():
            parts.append(f"{k}:{v}" if not isinstance(v, list) else f"{k}:{v[0]}")
        return ", ".join(parts)
    if isinstance(principal, list):
        return ", ".join(str(p) for p in principal)
    return str(principal)


def build_graph(policy: PolicyDoc) -> GraphData:
    G: nx.DiGraph = nx.DiGraph()

    policy_id = "policy_root"
    nodes: list[NodeData] = [NodeData(id=policy_id, label="Policy", node_type="policy")]
    G.add_node(policy_id)

    action_ids: dict[str, str] = {}
    resource_ids: dict[str, str] = {}
    seen_edges: set[tuple[str, str, str]] = set()
    edges: list[EdgeData] = []

    def _add_edge(source: str, target: str, edge_type: str) -> None:
        key = (source, target, edge_type)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append(EdgeData(source=source, target=target, edge_type=edge_type))
            G.add_edge(source, target)

    for idx, stmt in enumerate(policy.statement):
        effect_value = stmt.effect.value

        # ── Statement node ────────────────────────────────────────────
        stmt_id = f"stmt_{idx}"
        stmt_label = f"Stmt {idx} ({effect_value})"
        nodes.append(NodeData(
            id=stmt_id,
            label=stmt_label,
            node_type="statement",
            metadata={"effect": effect_value, "statement_idx": idx},
        ))
        G.add_node(stmt_id)
        _add_edge(policy_id, stmt_id, "CONTAINS")

        # ── Principal node ────────────────────────────────────────────
        if stmt.principal is not None:
            p_label = _principal_label(stmt.principal)
            p_id = _safe_id("principal", p_label[:60])
            if not G.has_node(p_id):
                nodes.append(NodeData(
                    id=p_id,
                    label=p_label,
                    node_type="principal",
                    metadata={"raw": json.dumps(stmt.principal)},
                ))
                G.add_node(p_id)
            _add_edge(p_id, policy_id, "TRUSTS")

        # ── Action nodes ──────────────────────────────────────────────
        for action in stmt.actions:
            risk_weight = _RISK_WEIGHTS.get(action, _DEFAULT_RISK_WEIGHT)
            if action not in action_ids:
                node_id = _safe_id("action", action)
                action_ids[action] = node_id
                nodes.append(NodeData(
                    id=node_id,
                    label=action,
                    node_type="action",
                    metadata={
                        "effect": effect_value,
                        "risk_weight": risk_weight,
                        "statement_idx": idx,
                    },
                ))
                G.add_node(node_id)
            _add_edge(stmt_id, action_ids[action], "GRANTS")

        # ── Resource nodes ────────────────────────────────────────────
        for resource in stmt.resources:
            if resource not in resource_ids:
                node_id = _safe_id("resource", resource)
                resource_ids[resource] = node_id
                nodes.append(NodeData(id=node_id, label=resource, node_type="resource"))
                G.add_node(node_id)
            for action in stmt.actions:
                if action in action_ids:
                    _add_edge(action_ids[action], resource_ids[resource], "ON_RESOURCE")

    return GraphData(nodes=nodes, edges=edges)
