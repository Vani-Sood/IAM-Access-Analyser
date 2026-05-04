"""Privilege escalation detection using HLD path queries."""
from __future__ import annotations

from dataclasses import dataclass

from app.analysis.graph_builder import GraphData
from app.analysis.hld import HLDEngine

DANGEROUS_ACTIONS: frozenset[str] = frozenset({
    "iam:*",
    "*",
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "sts:AssumeRole",
})

WILDCARD_RESOURCES: frozenset[str] = frozenset({"*", "arn:aws:iam::*:*", "arn:aws:iam:::*"})

_ACTION_DESCRIPTIONS: dict[str, str] = {
    "iam:*": "Wildcard IAM action grants full admin access",
    "*": "Wildcard action grants unrestricted access to all services",
    "iam:PassRole": "Allows passing roles to AWS services, enabling privilege escalation",
    "iam:CreatePolicyVersion": "Allows overwriting policy versions to gain elevated permissions",
    "iam:AttachRolePolicy": "Allows attaching arbitrary managed policies to roles",
    "iam:PutRolePolicy": "Allows injecting inline policies into roles",
    "sts:AssumeRole": "Allows assuming any IAM role",
}


@dataclass(frozen=True)
class PrivescPath:
    source_node: str
    target_node: str
    path_nodes: list[str]
    dangerous_actions: list[str]
    severity: str
    description: str


class PrivescDetector:
    """Detect privilege escalation paths in an IAM permission graph."""

    def __init__(self, graph: GraphData) -> None:
        self._graph = graph
        self._hld = HLDEngine(graph) if graph.nodes else None

    def detect(self) -> list[PrivescPath]:
        if not self._graph.nodes or self._hld is None:
            return []

        resource_nodes = {n.id: n for n in self._graph.nodes if n.node_type == "resource"}

        # Build resource → list of Allow-effect action labels
        allow_action_labels: dict[str, list[str]] = {}
        action_map = {n.id: n for n in self._graph.nodes if n.node_type == "action"}

        for edge in self._graph.edges:
            if edge.edge_type != "ON_RESOURCE":
                continue
            action_node = action_map.get(edge.source)
            if action_node is None:
                continue
            if action_node.metadata.get("effect", "Allow") != "Allow":
                continue
            label = action_node.label
            if label in DANGEROUS_ACTIONS:
                allow_action_labels.setdefault(edge.target, []).append(label)

        findings: list[PrivescPath] = []

        for resource_id, dangerous in allow_action_labels.items():
            resource_node = resource_nodes.get(resource_id)
            if resource_node is None:
                continue

            is_wildcard = resource_node.label in WILDCARD_RESOURCES
            deduped = list(dict.fromkeys(dangerous))  # preserve order, remove dups

            path = self._hld.path_nodes("policy_root", resource_id)
            if not path:
                path = [resource_id]

            severity = _compute_severity(deduped, is_wildcard)
            description = _build_description(deduped, resource_node.label, is_wildcard)

            findings.append(PrivescPath(
                source_node="policy_root",
                target_node=resource_id,
                path_nodes=path,
                dangerous_actions=deduped,
                severity=severity,
                description=description,
            ))

        return findings


def _compute_severity(dangerous_actions: list[str], is_wildcard: bool) -> str:
    # Multiple dangerous actions on wildcard (e.g. expanded iam:*) = CRITICAL
    if is_wildcard and len(dangerous_actions) >= 2:
        return "CRITICAL"
    if is_wildcard:
        return "HIGH"
    return "MEDIUM"


def _build_description(dangerous_actions: list[str], resource_label: str, is_wildcard: bool) -> str:
    if len(dangerous_actions) == 1:
        base = _ACTION_DESCRIPTIONS.get(dangerous_actions[0], f"Dangerous action {dangerous_actions[0]!r}")
    else:
        base = f"{len(dangerous_actions)} dangerous IAM actions grant escalated privileges"
    suffix = " via wildcard resource" if is_wildcard else f" on resource {resource_label!r}"
    return base + suffix
