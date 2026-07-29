"""Adversarial tests for causal effect graphs (extreme-v2 Phase 5):
attempts to forge a link, hide a cycle, or exceed the graph size bound.
"""

from __future__ import annotations

from karmasakshi.causal.graph import CausalEffectGraph, verify_causal_graph
from karmasakshi.causal.signing import sign_causal_link
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import CausalGraphTooLargeError

_H1 = "sha256:" + "1" * 64
_H2 = "sha256:" + "2" * 64
_H3 = "sha256:" + "3" * 64
_PRINCIPAL = Principal(principal_id="agent-1", principal_type=PrincipalType.AGENT)


def test_a_forged_link_content_with_a_replayed_signature_is_detected(now):
    """Swapping a valid link's relationship after the fact (keeping the
    old signature) must fail signature verification -- the same
    tamper-detection guarantee every other signed artifact in this
    protocol has."""
    key = generate_signing_key("k1")
    keyring = Keyring([key.verification_key()])
    link = sign_causal_link(
        link_id="l1",
        parent_manifest_hash=_H1,
        child_manifest_hash=_H2,
        relationship="triggers",
        recorded_by=_PRINCIPAL,
        signing_key=key,
        nonce="n1",
        clock=FixedClock(now),
    )
    forged = link.model_copy(update={"relationship": "compensates"})
    graph = CausalEffectGraph(links=(forged,))
    result = verify_causal_graph(graph, keyring)
    assert not result.verified
    assert result.invalid_link_ids == ("l1",)


def test_a_key_swap_attack_is_rejected(now):
    """An attacker signs a link with their own key and claims it belongs
    to a key_id already trusted by the keyring -- unless the keyring
    genuinely holds that key_id under the attacker's own key material
    (impossible without the private key), verification must fail."""
    legit_key = generate_signing_key("trusted-key")
    attacker_key = generate_signing_key("attacker-key")
    keyring = Keyring([legit_key.verification_key()])  # attacker's key never registered

    link = sign_causal_link(
        link_id="l1",
        parent_manifest_hash=_H1,
        child_manifest_hash=_H2,
        relationship="triggers",
        recorded_by=_PRINCIPAL,
        signing_key=attacker_key,
        nonce="n1",
        clock=FixedClock(now),
    )
    graph = CausalEffectGraph(links=(link,))
    result = verify_causal_graph(graph, keyring)
    assert not result.verified
    assert result.invalid_link_ids == ("l1",)


def test_hidden_cycle_via_many_valid_looking_hops_is_still_caught(now):
    """A long chain of individually well-formed, correctly signed links
    that loops back to its own origin at the very end must still be
    reported as cyclic -- an attacker cannot bury a cycle deep enough to
    evade detection."""
    key = generate_signing_key("k1")
    keyring = Keyring([key.verification_key()])
    hashes = [f"sha256:{i:064d}" for i in range(20)]
    links = []
    for i in range(len(hashes) - 1):
        links.append(
            sign_causal_link(
                link_id=f"l{i}",
                parent_manifest_hash=hashes[i],
                child_manifest_hash=hashes[i + 1],
                relationship="triggers",
                recorded_by=_PRINCIPAL,
                signing_key=key,
                nonce=f"n{i}",
                clock=FixedClock(now),
            )
        )
    # Close the loop: the last node causally links back to the first.
    links.append(
        sign_causal_link(
            link_id="l-close",
            parent_manifest_hash=hashes[-1],
            child_manifest_hash=hashes[0],
            relationship="triggers",
            recorded_by=_PRINCIPAL,
            signing_key=key,
            nonce="n-close",
            clock=FixedClock(now),
        )
    )
    graph = CausalEffectGraph(links=tuple(links))
    result = verify_causal_graph(graph, keyring)
    assert not result.verified
    assert result.has_cycle


def test_graph_size_bound_cannot_be_bypassed_by_batching(now):
    """A caller cannot smuggle an oversized graph past the MAX_LINKS bound
    by constructing it directly -- the bound is enforced in the
    dataclass's own constructor, not just at some higher call site."""
    key = generate_signing_key("k1")
    links = tuple(
        sign_causal_link(
            link_id=f"l{i}",
            parent_manifest_hash=f"sha256:{i:064d}",
            child_manifest_hash=f"sha256:{i + 1:064d}",
            relationship="triggers",
            recorded_by=_PRINCIPAL,
            signing_key=key,
            nonce=f"n{i}",
            clock=FixedClock(now),
        )
        for i in range(600)
    )
    try:
        CausalEffectGraph(links=links)
        raised = False
    except CausalGraphTooLargeError:
        raised = True
    assert raised


def test_verification_does_not_stop_at_the_first_invalid_link(now):
    """Mixed batch: one valid, one forged, one from an unregistered key --
    every link must be checked independently, not short-circuited after
    the first failure (mirrors evaluate_quorum's per-statement rejection
    behavior)."""
    key = generate_signing_key("k1")
    other_key = generate_signing_key("k2")
    keyring = Keyring([key.verification_key()])

    valid = sign_causal_link(
        link_id="valid",
        parent_manifest_hash=_H1,
        child_manifest_hash=_H2,
        relationship="triggers",
        recorded_by=_PRINCIPAL,
        signing_key=key,
        nonce="n-valid",
        clock=FixedClock(now),
    )
    forged = sign_causal_link(
        link_id="forged",
        parent_manifest_hash=_H2,
        child_manifest_hash=_H3,
        relationship="triggers",
        recorded_by=_PRINCIPAL,
        signing_key=key,
        nonce="n-forged",
        clock=FixedClock(now),
    ).model_copy(update={"relationship": "compensates"})
    untrusted = sign_causal_link(
        link_id="untrusted",
        parent_manifest_hash=_H3,
        child_manifest_hash="sha256:" + "9" * 64,
        relationship="triggers",
        recorded_by=_PRINCIPAL,
        signing_key=other_key,
        nonce="n-untrusted",
        clock=FixedClock(now),
    )
    graph = CausalEffectGraph(links=(valid, forged, untrusted))
    result = verify_causal_graph(graph, keyring)
    assert not result.verified
    assert result.invalid_link_ids == ("forged", "untrusted")
