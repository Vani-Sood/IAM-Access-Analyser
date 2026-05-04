"""Heavy-Light Decomposition for O(log N) path queries on the IAM permission graph.

Build: O(N), Path query: O(log N) chain jumps.
Operates on the spanning tree formed by CONTAINS / GRANTS / ON_RESOURCE edges.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.analysis.graph_builder import GraphData

_TREE_EDGE_TYPES = frozenset({"CONTAINS", "GRANTS", "ON_RESOURCE"})


@dataclass
class HLDEngine:
    """Heavy-Light Decomposition over the IAM permission graph spanning tree."""

    graph: GraphData

    _subtree_size: dict[str, int] = field(default_factory=dict, init=False)
    _heavy: dict[str, str | None] = field(default_factory=dict, init=False)
    _parent: dict[str, str | None] = field(default_factory=dict, init=False)
    _depth: dict[str, int] = field(default_factory=dict, init=False)
    _chain_head: dict[str, str] = field(default_factory=dict, init=False)
    # chain_id → ordered list of node IDs (top to bottom)
    _chains: list[list[str]] = field(default_factory=list, init=False)
    # node_id → (chain_id, position_within_chain)
    _node_chain: dict[str, tuple[int, int]] = field(default_factory=dict, init=False)
    # chain head → chain_id
    _head_to_chain: dict[str, int] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self._build()

    # ── Build ──────────────────────────────────────────────────────────────

    def _build(self) -> None:
        if not self.graph.nodes:
            return

        adj: dict[str, list[str]] = {n.id: [] for n in self.graph.nodes}
        for edge in self.graph.edges:
            if edge.edge_type in _TREE_EDGE_TYPES:
                adj[edge.source].append(edge.target)

        incoming = {
            e.target
            for e in self.graph.edges
            if e.edge_type in _TREE_EDGE_TYPES
        }
        candidates = [n.id for n in self.graph.nodes if n.id not in incoming]
        if not candidates:
            root = self.graph.nodes[0].id
        else:
            root = next((c for c in candidates if c == "policy_root"), candidates[0])

        self._parent[root] = None
        self._depth[root] = 0
        self._dfs_sizes(root, adj)
        self._dfs_chains(root, root, adj)

    def _dfs_sizes(self, root: str, adj: dict[str, list[str]]) -> None:
        """Iterative post-order DFS: subtree sizes, parents, depths, heavy children."""
        order: list[str] = []
        stack = [root]
        visited: set[str] = {root}

        while stack:
            node = stack.pop()
            order.append(node)
            self._subtree_size[node] = 1
            for child in adj[node]:
                if child not in visited:
                    visited.add(child)
                    self._parent[child] = node
                    self._depth[child] = self._depth[node] + 1
                    stack.append(child)

        # Post-order: leaves first
        for node in reversed(order):
            children = [c for c in adj[node] if self._parent.get(c) == node]
            for child in children:
                self._subtree_size[node] += self._subtree_size.get(child, 0)
            self._heavy[node] = (
                max(children, key=lambda c: self._subtree_size.get(c, 0))
                if children else None
            )

    def _dfs_chains(self, root: str, head: str, adj: dict[str, list[str]]) -> None:
        """Iterative DFS: assign chain heads, build chain lists top-to-bottom."""
        # Stack: (node, chain_head_for_this_node)
        stack = [(root, head)]

        while stack:
            node, cur_head = stack.pop()
            if node in self._chain_head:
                continue

            self._chain_head[node] = cur_head

            # Get or create the chain for cur_head
            if cur_head not in self._head_to_chain:
                chain_id = len(self._chains)
                self._chains.append([])
                self._head_to_chain[cur_head] = chain_id
            chain_id = self._head_to_chain[cur_head]

            pos = len(self._chains[chain_id])
            self._chains[chain_id].append(node)
            self._node_chain[node] = (chain_id, pos)

            children = [c for c in adj[node] if self._parent.get(c) == node]
            heavy = self._heavy.get(node)

            # Push light children first (they get new chains)
            for child in children:
                if child != heavy:
                    stack.append((child, child))

            # Push heavy child last (LIFO → processed first, continues current chain)
            if heavy is not None:
                stack.append((heavy, cur_head))

    # ── Path query ─────────────────────────────────────────────────────────

    def path_nodes(self, u: str, v: str) -> list[str]:
        """Return node IDs on the spanning-tree path from u to v (both inclusive).

        Returns [] if either node is absent from the spanning tree.
        """
        if u not in self._chain_head or v not in self._chain_head:
            return []
        if u == v:
            return [u]

        # Collect segments walking up from both ends to their shared chain
        u_seg: list[str] = []
        v_seg: list[str] = []

        while self._chain_head[u] != self._chain_head[v]:
            u_head_depth = self._depth.get(self._chain_head[u], -1)
            v_head_depth = self._depth.get(self._chain_head[v], -1)

            # Walk the deeper chain head up
            if u_head_depth >= v_head_depth:
                head_u = self._chain_head[u]
                chain_id, pos_u = self._node_chain[u]
                _, pos_head = self._node_chain[head_u]
                u_seg.extend(self._chains[chain_id][pos_head : pos_u + 1])
                parent_of_head = self._parent.get(head_u)
                if parent_of_head is None:
                    break
                u = parent_of_head
            else:
                head_v = self._chain_head[v]
                chain_id, pos_v = self._node_chain[v]
                _, pos_head = self._node_chain[head_v]
                v_seg.extend(self._chains[chain_id][pos_head : pos_v + 1])
                parent_of_head = self._parent.get(head_v)
                if parent_of_head is None:
                    break
                v = parent_of_head

        # u and v now share a chain: collect the segment between them
        if self._chain_head.get(u) == self._chain_head.get(v):
            chain_id_u, pos_u2 = self._node_chain[u]
            _, pos_v2 = self._node_chain[v]
            lo, hi = min(pos_u2, pos_v2), max(pos_u2, pos_v2)
            middle = self._chains[chain_id_u][lo : hi + 1]
        else:
            middle = []

        # u_seg is gathered going up from original u (so reverse to get top-down),
        # v_seg likewise; middle is already top-down
        combined = list(reversed(u_seg)) + middle + list(reversed(v_seg))

        # Deduplicate preserving order
        seen: set[str] = set()
        result: list[str] = []
        for node in combined:
            if node not in seen:
                seen.add(node)
                result.append(node)
        return result

    def path_permissions(self, u: str, v: str) -> set[str]:
        """Return set of action labels on the spanning-tree path from u to v."""
        nodes = self.path_nodes(u, v)
        node_map = {n.id: n for n in self.graph.nodes}
        perms: set[str] = set()
        for nid in nodes:
            node = node_map.get(nid)
            if node and node.node_type == "action":
                perms.add(node.label)
        return perms
