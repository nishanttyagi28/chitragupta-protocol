"""Deterministic topological ordering of causal graph nodes for sagas."""

from __future__ import annotations

from collections import defaultdict

from karmasakshi.causal.graph import CausalEffectGraph
from karmasakshi.errors import SagaOrderingError

MAX_SAGA_STEPS = 256


def topo_manifest_hashes(graph: CausalEffectGraph) -> tuple[str, ...]:
    """Return a deterministic Kahn topo order of ``graph`` nodes.

    Tie-break among zero-indegree nodes by lexicographic ``manifest_hash``
    so the same graph always yields the same saga step order regardless of
    link presentation order.
    """
    nodes = set(graph.node_manifest_hashes)
    if len(nodes) > MAX_SAGA_STEPS:
        raise SagaOrderingError(f"saga cannot exceed {MAX_SAGA_STEPS} steps")
    adjacency: dict[str, list[str]] = defaultdict(list)
    indegree = dict.fromkeys(nodes, 0)
    for link in graph.links:
        parent = link.parent_manifest_hash
        child = link.child_manifest_hash
        adjacency[parent].append(child)
        indegree[child] += 1
    for children in adjacency.values():
        children.sort()

    ready = sorted(node for node, degree in indegree.items() if degree == 0)
    ordered: list[str] = []
    while ready:
        node = ready.pop(0)
        ordered.append(node)
        for child in adjacency[node]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort()
    if len(ordered) != len(nodes):
        raise SagaOrderingError("causal graph must be acyclic for saga ordering")
    return tuple(ordered)


__all__ = ["MAX_SAGA_STEPS", "topo_manifest_hashes"]
