from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.causal import build_causal_graph, sign_causal_link
from karmasakshi.errors import InvalidSignatureError


def _hash(char: str) -> str:
    return "sha256:" + char * 64


def _link(parent, child, *, key, now, relation="causes", link_id=None):
    return sign_causal_link(
        parent_manifest_hash=parent,
        child_manifest_hash=child,
        relation=relation,
        signing_key=key,
        created_at=now,
        link_id=link_id,
    )


def test_graph_is_deterministic_and_verifiable(issuer_signing_key, keyring, now):
    a, b, c = _hash("a"), _hash("b"), _hash("c")
    ab = _link(a, b, key=issuer_signing_key, now=now, link_id="ab")
    bc = _link(b, c, key=issuer_signing_key, now=now, link_id="bc")

    graph = build_causal_graph(
        graph_id="refund-flow",
        node_manifest_hashes=(c, a, b),
        links=(bc, ab),
    )
    same = build_causal_graph(
        graph_id="refund-flow",
        node_manifest_hashes=(a, b, c),
        links=(ab, bc),
    )

    graph.verify(keyring)
    assert graph.canonical_hash() == same.canonical_hash()
    assert graph.roots() == (a,)
    assert graph.ancestors_of(c) == (a, b)


def test_cycle_is_rejected(issuer_signing_key, now):
    a, b = _hash("a"), _hash("b")
    with pytest.raises(ValueError, match="acyclic"):
        build_causal_graph(
            node_manifest_hashes=(a, b),
            links=(
                _link(a, b, key=issuer_signing_key, now=now),
                _link(b, a, key=issuer_signing_key, now=now + timedelta(seconds=1)),
            ),
        )


def test_missing_endpoint_and_self_link_are_rejected(issuer_signing_key, now):
    a, b = _hash("a"), _hash("b")
    with pytest.raises(ValueError, match="endpoint"):
        build_causal_graph(
            node_manifest_hashes=(a,),
            links=(_link(a, b, key=issuer_signing_key, now=now),),
        )
    with pytest.raises(ValueError, match="itself"):
        build_causal_graph(
            node_manifest_hashes=(a,),
            links=(_link(a, a, key=issuer_signing_key, now=now),),
        )


def test_tampered_link_fails_signature(issuer_signing_key, keyring, now):
    a, b = _hash("a"), _hash("b")
    link = _link(a, b, key=issuer_signing_key, now=now)
    tampered = link.model_copy(update={"relation": "compensates"})
    graph = build_causal_graph(node_manifest_hashes=(a, b), links=(tampered,))

    with pytest.raises(InvalidSignatureError):
        graph.verify(keyring)


def test_ancestor_query_rejects_unknown_node(issuer_signing_key, now):
    a = _hash("a")
    graph = build_causal_graph(node_manifest_hashes=(a,), links=())
    with pytest.raises(Exception, match="not a node"):
        graph.ancestors_of(_hash("b"))
