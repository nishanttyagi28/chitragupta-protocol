"""Causal effect graphs: a set of signed ``CausalLink`` edges over
manifest hashes, with cycle detection and independent signature
verification (extreme-v2 Phase 5).

**Advisory only in this release**, exactly like Phase 1's Effect
Intelligence Engine: nothing in ``authorize()``/``commit()`` reads or
enforces anything here. A ``CausalEffectGraph`` is a verifiable *record*
of causality for the Action Passport (the PROVE step), not a new
authorization gate. See docs/causal-effect-graphs.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from karmasakshi.causal.model import CausalLink
from karmasakshi.causal.signing import verify_causal_link_signature
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.errors import CausalGraphTooLargeError, KarmaSakshiError

#: Resource-protection bound, consistent with the other small, fixed-size
#: bounds in this codebase (``ApprovalPolicy.max_statements_considered``,
#: ``RoleAssignment.MAX_ROLE_ASSIGNMENTS``).
MAX_LINKS = 512


@dataclass(frozen=True)
class CausalEffectGraph:
    """An immutable set of causal links. Node identities are manifest
    hashes; edges are signed ``CausalLink``s. Structurally bounded --
    construction raises :class:`CausalGraphTooLargeError` above
    ``MAX_LINKS`` links rather than silently truncating."""

    links: tuple[CausalLink, ...]

    def __post_init__(self) -> None:
        if len(self.links) > MAX_LINKS:
            raise CausalGraphTooLargeError(
                f"causal graph has {len(self.links)} links, exceeding the {MAX_LINKS} bound"
            )

    def parents_of(self, manifest_hash: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    link.parent_manifest_hash
                    for link in self.links
                    if link.child_manifest_hash == manifest_hash
                }
            )
        )

    def children_of(self, manifest_hash: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    link.child_manifest_hash
                    for link in self.links
                    if link.parent_manifest_hash == manifest_hash
                }
            )
        )

    def ancestors_of(self, manifest_hash: str) -> tuple[str, ...]:
        """Every manifest hash reachable by walking parent edges upward
        from ``manifest_hash``, cycle-safe (a visited set bounds the walk
        even if the graph turns out to be cyclic)."""
        visited: set[str] = set()
        frontier = list(self.parents_of(manifest_hash))
        while frontier:
            node = frontier.pop()
            if node in visited:
                continue
            visited.add(node)
            frontier.extend(self.parents_of(node))
        return tuple(sorted(visited))

    def has_cycle(self) -> bool:
        """Standard directed-graph cycle detection (iterative DFS with
        white/gray/black coloring, so an adversarially long chain never
        risks Python's recursion limit) -- terminates even on a cyclic
        graph."""
        children: dict[str, list[str]] = {}
        nodes: set[str] = set()
        for link in self.links:
            children.setdefault(link.parent_manifest_hash, []).append(link.child_manifest_hash)
            nodes.add(link.parent_manifest_hash)
            nodes.add(link.child_manifest_hash)

        white, gray, black = 0, 1, 2
        color: dict[str, int] = dict.fromkeys(nodes, white)

        for start in sorted(nodes):
            if color[start] != white:
                continue
            # Each stack frame is (node, iterator-index-into-sorted-children);
            # entering a node marks it gray, leaving it (all children done)
            # marks it black -- a gray child found again means a back-edge.
            stack: list[tuple[str, list[str], int]] = [(start, sorted(children.get(start, [])), 0)]
            color[start] = gray
            while stack:
                node, kids, idx = stack[-1]
                if idx >= len(kids):
                    color[node] = black
                    stack.pop()
                    continue
                stack[-1] = (node, kids, idx + 1)
                child = kids[idx]
                if color[child] == gray:
                    return True
                if color[child] == white:
                    color[child] = gray
                    stack.append((child, sorted(children.get(child, [])), 0))
        return False


@dataclass(frozen=True)
class CausalGraphVerificationResult:
    """The outcome of independently verifying every link's signature and
    checking the graph for cycles. Deterministic given the same link set
    (verification order does not affect the result)."""

    verified: bool
    has_cycle: bool
    invalid_link_ids: tuple[str, ...]
    node_count: int
    edge_count: int
    reason: str


def verify_causal_graph(
    graph: CausalEffectGraph, keyring: Keyring
) -> CausalGraphVerificationResult:
    """Verify every link's signature and check for cycles.

    A single bad signature never raises -- it's recorded in
    ``invalid_link_ids`` and verification continues, mirroring how
    ``evaluate_quorum`` records per-statement rejections rather than
    aborting the whole evaluation.
    """
    invalid: list[str] = []
    for link in graph.links:
        try:
            verify_causal_link_signature(link, keyring)
        except KarmaSakshiError:
            invalid.append(link.link_id)

    cyclic = graph.has_cycle()
    nodes: set[str] = set()
    for link in graph.links:
        nodes.add(link.parent_manifest_hash)
        nodes.add(link.child_manifest_hash)

    verified = not invalid and not cyclic
    if verified:
        reason = "all links verified, no cycle detected"
    else:
        parts = []
        if invalid:
            parts.append(f"{len(invalid)} link(s) failed signature verification")
        if cyclic:
            parts.append("a cycle was detected")
        reason = "; ".join(parts)

    return CausalGraphVerificationResult(
        verified=verified,
        has_cycle=cyclic,
        invalid_link_ids=tuple(sorted(invalid)),
        node_count=len(nodes),
        edge_count=len(graph.links),
        reason=reason,
    )


__all__ = ["MAX_LINKS", "CausalEffectGraph", "CausalGraphVerificationResult", "verify_causal_graph"]
