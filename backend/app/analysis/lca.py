"""LCA Engine: Euler tour + sparse table RMQ, O(N log N) build / O(1) query."""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from app.analysis.graph_builder import GraphData

_TREE_EDGE_TYPES = frozenset({"CONTAINS", "GRANTS", "ON_RESOURCE"})


@dataclass
class LCAEngine:
    """Lowest Common Ancestor over the IAM permission graph spanning tree.

    Uses Euler tour + sparse table RMQ:
    - Build: O(N log N)
    - Query: O(1)

    Only CONTAINS / GRANTS / ON_RESOURCE edges form the spanning tree.
    TRUSTS edges are ignored to avoid cycles.
    """

    graph: GraphData

    euler: list[str] = field(default_factory=list, init=False)
    first: dict[str, int] = field(default_factory=dict, init=False)
    depth: dict[str, int] = field(default_factory=dict, init=False)
    _sparse: list[list[int]] = field(default_factory=list, init=False)
    _log: int = field(default=0, init=False)
    _parent: dict[str, str | None] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self._build()

    # ── Build ──────────────────────────────────────────────────────────────

    def _build(self) -> None:
        if not self.graph.nodes:
            return

        # Adjacency list: only tree edges
        adj: dict[str, list[str]] = {n.id: [] for n in self.graph.nodes}
        for edge in self.graph.edges:
            if edge.edge_type in _TREE_EDGE_TYPES:
                adj[edge.source].append(edge.target)

        # Root = node with no incoming tree edges
        incoming = {
            e.target
            for e in self.graph.edges
            if e.edge_type in _TREE_EDGE_TYPES
        }
        candidates = [n.id for n in self.graph.nodes if n.id not in incoming]
        if not candidates:
            # Fallback: first node
            root = self.graph.nodes[0].id
        else:
            # Prefer policy_root if present
            root = next((c for c in candidates if c == "policy_root"), candidates[0])

        # Iterative DFS to build Euler tour (avoids recursion limit on large graphs)
        self.euler = []
        self.first = {}
        self.depth = {root: 0}
        self._parent = {root: None}
        visited: set[str] = set()

        # Stack entries: (node, child_index)
        stack: list[tuple[str, int]] = [(root, 0)]
        visited.add(root)
        self.first[root] = 0
        self.euler.append(root)

        while stack:
            node, ci = stack[-1]
            children = adj[node]
            if ci < len(children):
                stack[-1] = (node, ci + 1)
                child = children[ci]
                if child not in visited:
                    visited.add(child)
                    self.depth[child] = self.depth[node] + 1
                    self._parent[child] = node
                    self.first[child] = len(self.euler)
                    self.euler.append(child)
                    stack.append((child, 0))
            else:
                stack.pop()
                if stack:
                    parent = stack[-1][0]
                    self.euler.append(parent)

        self._build_sparse_table()

    def _build_sparse_table(self) -> None:
        n = len(self.euler)
        if n == 0:
            return
        self._log = max(1, int(math.log2(n)) + 1)
        self._sparse = [[0] * n for _ in range(self._log)]

        for i in range(n):
            self._sparse[0][i] = i

        for k in range(1, self._log):
            half = 1 << (k - 1)
            for i in range(n - (1 << k) + 1):
                left = self._sparse[k - 1][i]
                right = self._sparse[k - 1][i + half]
                if self.depth[self.euler[left]] <= self.depth[self.euler[right]]:
                    self._sparse[k][i] = left
                else:
                    self._sparse[k][i] = right

    # ── Query ──────────────────────────────────────────────────────────────

    def _rmq(self, l: int, r: int) -> int:
        """Return index in euler array with minimum depth in [l, r]."""
        if l > r:
            l, r = r, l
        k = int(math.log2(r - l + 1)) if r > l else 0
        left = self._sparse[k][l]
        right = self._sparse[k][r - (1 << k) + 1]
        if self.depth[self.euler[left]] <= self.depth[self.euler[right]]:
            return left
        return right

    def lca(self, u: str, v: str) -> str | None:
        """Return LCA node ID of u and v, or None if either is not in the tree."""
        if u not in self.first or v not in self.first:
            return None
        lu, lv = self.first[u], self.first[v]
        if lu == lv:
            return u
        idx = self._rmq(lu, lv)
        return self.euler[idx]

    def ancestors(self, node: str) -> list[str]:
        """Return path from node to root (inclusive), root last. Empty if not in tree."""
        if node not in self._parent:
            return []
        path: list[str] = []
        current: str | None = node
        while current is not None:
            path.append(current)
            current = self._parent.get(current)
        return path
