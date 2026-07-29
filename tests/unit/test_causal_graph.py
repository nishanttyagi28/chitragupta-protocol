from __future__ import annotations

import pytest

from karmasakshi.causal import (
    CausalEffectGraph,
    sign_causal_link,
    verify_causal_graph,
    verify_causal_link_signature,
)
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import CausalGraphTooLargeError, InvalidSignatureError, UnknownKeyError

_H1 = "sha256:" + "1" * 64
_H2 = "sha256:" + "2" * 64
_H3 = "sha256:" + "3" * 64


def _principal(pid, ptype=PrincipalType.AGENT):
    return Principal(principal_id=pid, principal_type=ptype)


_counter = iter(range(1_000_000))


def _link(key, parent, child, *, now, relationship="triggers", link_id=None, nonce=None):
    n = next(_counter)
    return sign_causal_link(
        link_id=link_id or f"link-{n}",
        parent_manifest_hash=parent,
        child_manifest_hash=child,
        relationship=relationship,
        recorded_by=_principal("agent-1"),
        signing_key=key,
        nonce=nonce or f"nonce-{n}",
        clock=FixedClock(now),
    )


# --- CausalLink -----------------------------------------------------------


def test_causal_link_rejects_self_reference(now):
    key = generate_signing_key("k1")
    with pytest.raises(ValueError, match="itself"):
        _link(key, _H1, _H1, now=now)


def test_causal_link_rejects_malformed_hash(now):
    key = generate_signing_key("k1")
    with pytest.raises(ValueError):
        sign_causal_link(
            link_id="l1",
            parent_manifest_hash="not-a-hash",
            child_manifest_hash=_H2,
            relationship="triggers",
            recorded_by=_principal("agent-1"),
            signing_key=key,
            nonce="n1",
            clock=FixedClock(now),
        )


def test_causal_link_signing_round_trip_verifies(now):
    key = generate_signing_key("k1")
    keyring = Keyring([key.verification_key()])
    link = _link(key, _H1, _H2, now=now)
    verify_causal_link_signature(link, keyring)  # does not raise


def test_causal_link_unknown_key_fails_closed(now):
    key = generate_signing_key("k1")
    other_keyring = Keyring([generate_signing_key("k2").verification_key()])
    link = _link(key, _H1, _H2, now=now)
    with pytest.raises(UnknownKeyError):
        verify_causal_link_signature(link, other_keyring)


def test_causal_link_tampered_content_fails_signature_verification(now):
    key = generate_signing_key("k1")
    keyring = Keyring([key.verification_key()])
    link = _link(key, _H1, _H2, now=now)
    tampered = link.model_copy(update={"relationship": "compensates"})
    with pytest.raises(InvalidSignatureError):
        verify_causal_link_signature(tampered, keyring)


def test_causal_link_agent_recorded_by_is_allowed(now):
    """Unlike ApprovalStatement/PolicyBundle, invariant #30 does not apply
    here -- a causal link is a factual record, not an authorization
    decision, so an agent principal may record one."""
    key = generate_signing_key("k1")
    link = _link(key, _H1, _H2, now=now)
    assert link.recorded_by.principal_type == PrincipalType.AGENT


# --- CausalEffectGraph ------------------------------------------------------


def test_graph_rejects_oversized_link_set(now):
    key = generate_signing_key("k1")
    links = tuple(
        _link(key, f"sha256:{i:064d}", f"sha256:{i + 1:064d}", now=now, link_id=f"l{i}")
        for i in range(513)
    )
    with pytest.raises(CausalGraphTooLargeError):
        CausalEffectGraph(links=links)


def test_graph_parents_and_children_of():
    key = generate_signing_key("k1")
    from datetime import datetime, timezone

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    l1 = _link(key, _H1, _H2, now=now)
    l2 = _link(key, _H1, _H3, now=now, link_id="l2")
    graph = CausalEffectGraph(links=(l1, l2))
    assert graph.children_of(_H1) == (_H2, _H3)
    assert graph.parents_of(_H2) == (_H1,)
    assert graph.parents_of(_H1) == ()


def test_graph_ancestors_of_transitive_chain(now):
    key = generate_signing_key("k1")
    l1 = _link(key, _H1, _H2, now=now, link_id="l1")
    l2 = _link(key, _H2, _H3, now=now, link_id="l2")
    graph = CausalEffectGraph(links=(l1, l2))
    assert graph.ancestors_of(_H3) == tuple(sorted((_H1, _H2)))
    assert graph.ancestors_of(_H1) == ()


def test_graph_has_cycle_detects_direct_and_transitive_cycles(now):
    key = generate_signing_key("k1")
    acyclic = CausalEffectGraph(links=(_link(key, _H1, _H2, now=now, link_id="l1"),))
    assert not acyclic.has_cycle()

    cyclic = CausalEffectGraph(
        links=(
            _link(key, _H1, _H2, now=now, link_id="l1"),
            _link(key, _H2, _H3, now=now, link_id="l2"),
            _link(key, _H3, _H1, now=now, link_id="l3"),
        )
    )
    assert cyclic.has_cycle()


def test_graph_ancestors_of_is_cycle_safe(now):
    """A cyclic graph must not infinite-loop the ancestor walk."""
    key = generate_signing_key("k1")
    graph = CausalEffectGraph(
        links=(
            _link(key, _H1, _H2, now=now, link_id="l1"),
            _link(key, _H2, _H1, now=now, link_id="l2"),
        )
    )
    ancestors = graph.ancestors_of(_H2)
    # H1 -> H2 -> H1 is a 2-cycle: walking parents from H2 reaches H1, then
    # H1's own parent (H2) again -- both nodes are legitimately "ancestors"
    # in a cyclic graph; what matters is the walk terminates at all.
    assert ancestors == tuple(sorted((_H1, _H2)))


# --- verify_causal_graph -----------------------------------------------------


def test_verify_causal_graph_all_valid_no_cycle(now):
    key = generate_signing_key("k1")
    keyring = Keyring([key.verification_key()])
    l1 = _link(key, _H1, _H2, now=now, link_id="l1")
    l2 = _link(key, _H2, _H3, now=now, link_id="l2")
    graph = CausalEffectGraph(links=(l1, l2))
    result = verify_causal_graph(graph, keyring)
    assert result.verified
    assert not result.has_cycle
    assert result.invalid_link_ids == ()
    assert result.node_count == 3
    assert result.edge_count == 2


def test_verify_causal_graph_reports_invalid_signature_without_raising(now):
    key = generate_signing_key("k1")
    other_keyring = Keyring([generate_signing_key("k2").verification_key()])
    link = _link(key, _H1, _H2, now=now, link_id="l1")
    graph = CausalEffectGraph(links=(link,))
    result = verify_causal_graph(graph, other_keyring)
    assert not result.verified
    assert result.invalid_link_ids == ("l1",)


def test_verify_causal_graph_reports_cycle(now):
    key = generate_signing_key("k1")
    keyring = Keyring([key.verification_key()])
    graph = CausalEffectGraph(
        links=(
            _link(key, _H1, _H2, now=now, link_id="l1"),
            _link(key, _H2, _H1, now=now, link_id="l2"),
        )
    )
    result = verify_causal_graph(graph, keyring)
    assert not result.verified
    assert result.has_cycle
