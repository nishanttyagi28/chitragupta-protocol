"""Atomic plan authorization helpers for sealed causal effect graphs.

Phase 6 lets a grant bind to *either* a decision envelope *or* one sealed
causal graph (never both). Graph-bound authorization means: the exact
manifest being authorized must be a node of the presented, signature-verified
graph, and ``commit()`` re-checks membership against the same graph hash.

This module does not invent execution ordering or parent-state propagation
(those remain deferred; see docs/causal-effect-graphs.md). It only provides
the deterministic membership gate required for plan-scoped grants.
"""

from __future__ import annotations

from karmasakshi.causal.graph import CausalEffectGraph
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.errors import AtomicPlanError, CausalGraphError


def assert_manifest_in_plan(
    manifest_hash: str,
    graph: CausalEffectGraph,
    *,
    keyring: Keyring | None = None,
) -> None:
    """Raise if ``manifest_hash`` is not a verified node of ``graph``.

    When ``keyring`` is provided, every causal link signature is verified
    first (fail closed on unknown keys / bad signatures).
    """
    if keyring is not None:
        try:
            graph.verify(keyring)
        except Exception as exc:
            raise AtomicPlanError(
                f"causal graph {graph.graph_id} failed verification: {exc}"
            ) from exc
    if manifest_hash not in graph.node_manifest_hashes:
        raise AtomicPlanError(
            f"manifest hash {manifest_hash} is not a node of causal graph "
            f"{graph.graph_id} (atomic plan authorization requires membership)"
        )


def require_matching_plan_hash(graph: CausalEffectGraph, expected_hash: str) -> None:
    actual = graph.canonical_hash()
    if actual != expected_hash:
        raise AtomicPlanError(
            f"causal graph hash mismatch: recomputed {actual} != expected {expected_hash}"
        )


def plan_node_count(graph: CausalEffectGraph) -> int:
    return len(graph.node_manifest_hashes)


__all__ = [
    "assert_manifest_in_plan",
    "plan_node_count",
    "require_matching_plan_hash",
]

# Re-export for callers that only import this module.
_ = CausalGraphError
