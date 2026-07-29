"""Property-based tests for causal effect graphs (extreme-v2 Phase 5):
cycle detection and verification must be deterministic regardless of
link order, and cycle detection must terminate on graphs an adversary
constructs specifically to be as deep or as cyclic as the size bound
allows.
"""

from __future__ import annotations

from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from karmasakshi.causal.graph import CausalEffectGraph
from karmasakshi.causal.model import CausalLink
from karmasakshi.crypto import generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType

_KEY = generate_signing_key("prop-key")
_PRINCIPAL = Principal(principal_id="agent-1", principal_type=PrincipalType.AGENT)
_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _hash_for(n: int) -> str:
    return f"sha256:{n:064d}"


def _signed_link(link_id: str, parent: str, child: str) -> CausalLink:
    unsigned = CausalLink(
        link_id=link_id,
        parent_manifest_hash=parent,
        child_manifest_hash=child,
        relationship="triggers",
        recorded_by=_PRINCIPAL,
        recorded_at=_NOW,
        nonce=f"nonce-{link_id}",
        key_id=_KEY.key_id,
        algorithm=_KEY.algorithm,
        signature=None,
    )
    signature = _KEY.sign(unsigned.canonical_hash().encode("utf-8"))
    return unsigned.model_copy(update={"signature": signature})


@st.composite
def _edge_lists(draw: st.DrawFn) -> tuple[tuple[int, int], ...]:
    n = draw(st.integers(min_value=0, max_value=10))
    pairs = draw(
        st.lists(
            st.tuples(st.integers(0, 9), st.integers(0, 9)).filter(lambda p: p[0] != p[1]),
            min_size=n,
            max_size=n,
            unique=True,
        )
    )
    return tuple(pairs)


def _graph_from_edges(edges: tuple[tuple[int, int], ...]) -> CausalEffectGraph:
    links = tuple(
        _signed_link(f"l{i}", _hash_for(a), _hash_for(b)) for i, (a, b) in enumerate(edges)
    )
    return CausalEffectGraph(links=links)


@given(edges=_edge_lists())
@settings(max_examples=100)
def test_has_cycle_is_independent_of_link_order(edges):
    graph = _graph_from_edges(edges)
    reordered = CausalEffectGraph(links=tuple(reversed(graph.links)))
    assert graph.has_cycle() == reordered.has_cycle()


@given(edges=_edge_lists())
@settings(max_examples=100)
def test_ancestors_of_is_independent_of_link_order(edges):
    graph = _graph_from_edges(edges)
    reordered = CausalEffectGraph(links=tuple(reversed(graph.links)))
    for n in range(10):
        h = _hash_for(n)
        assert graph.ancestors_of(h) == reordered.ancestors_of(h)


def test_has_cycle_terminates_on_a_long_chain_at_the_size_bound():
    """A 511-edge simple chain (just under MAX_LINKS) must not raise a
    recursion error and must correctly report no cycle."""
    edges = tuple((i, i + 1) for i in range(511))
    graph = _graph_from_edges(edges)
    assert graph.has_cycle() is False


def test_has_cycle_terminates_on_a_self_loop_free_but_densely_cyclic_graph():
    """A graph where every node points to every other node (a near-complete
    digraph over 8 nodes) is maximally cyclic; detection must still
    terminate promptly and report True."""
    edges = tuple((a, b) for a in range(8) for b in range(8) if a != b)
    graph = _graph_from_edges(edges)
    assert graph.has_cycle() is True
