"""Unit tests for independent witness quorum (Phase 9)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.engine.witness_quorum import assert_witness_quorum
from karmasakshi.errors import (
    WitnessBatchTooLargeError,
    WitnessIssuerNotAuthorizedError,
    WitnessQuorumNotMetError,
)
from karmasakshi.witness import (
    WitnessPolicy,
    evaluate_witness_quorum,
    sign_witness_statement,
)

_MANIFEST_HASH = "sha256:" + "a" * 64
_DIGEST = "digest-observed-1"
_OTHER_DIGEST = "digest-other"


def _principal(pid: str, ptype: PrincipalType = PrincipalType.HUMAN) -> Principal:
    return Principal(principal_id=pid, principal_type=ptype)


@pytest.fixture
def actor():
    return _principal("actor-agent", PrincipalType.AGENT)


@pytest.fixture
def subject():
    return _principal("executor-agent", PrincipalType.AGENT)


@pytest.fixture
def witness_keys():
    return {name: generate_signing_key(f"wkey-{name}") for name in ("w1", "w2", "w3")}


@pytest.fixture
def keyring(witness_keys):
    return Keyring([k.verification_key() for k in witness_keys.values()])


def _stmt(
    witness_keys,
    name,
    *,
    now,
    policy: WitnessPolicy,
    digest=_DIGEST,
    matched=True,
    manifest_hash=_MANIFEST_HASH,
    ttl=3600,
    statement_id=None,
    witness_type=PrincipalType.HUMAN,
):
    return sign_witness_statement(
        statement_id=statement_id or f"wstmt-{name}",
        manifest_hash=manifest_hash,
        witness_policy_hash=policy.policy_hash(),
        observed_after_state_digest=digest,
        matched_expected=matched,
        witness=_principal(name, witness_type),
        signing_key=witness_keys[name],
        expires_at=now + timedelta(seconds=ttl),
        nonce=f"nonce-{name}",
        clock=FixedClock(now),
    )


def test_single_witness_satisfies_default_policy(witness_keys, keyring, actor, subject, now):
    policy = WitnessPolicy(required_witnesses=1)
    stmt = _stmt(witness_keys, "w1", now=now, policy=policy)
    result = evaluate_witness_quorum(
        [stmt],
        policy,
        manifest_hash=_MANIFEST_HASH,
        expected_after_state_digest=_DIGEST,
        actor=actor,
        subject=subject,
        keyring=keyring,
        now=now,
    )
    assert result.satisfied
    assert result.accepted_witness_ids == ("w1",)
    assert result.witness_set_hash is not None
    assert result.witness_policy_hash == policy.policy_hash()


def test_two_of_three_required(witness_keys, keyring, actor, subject, now):
    policy = WitnessPolicy(required_witnesses=2)
    stmts = [
        _stmt(witness_keys, "w1", now=now, policy=policy),
        _stmt(witness_keys, "w2", now=now, policy=policy),
    ]
    result = evaluate_witness_quorum(
        stmts,
        policy,
        manifest_hash=_MANIFEST_HASH,
        expected_after_state_digest=_DIGEST,
        actor=actor,
        subject=subject,
        keyring=keyring,
        now=now,
    )
    assert result.satisfied
    assert set(result.accepted_witness_ids) == {"w1", "w2"}


def test_order_independent_hash(witness_keys, keyring, actor, subject, now):
    policy = WitnessPolicy(required_witnesses=2)
    a = _stmt(witness_keys, "w1", now=now, policy=policy)
    b = _stmt(witness_keys, "w2", now=now, policy=policy)
    kwargs = {
        "policy": policy,
        "manifest_hash": _MANIFEST_HASH,
        "expected_after_state_digest": _DIGEST,
        "actor": actor,
        "subject": subject,
        "keyring": keyring,
        "now": now,
    }
    r1 = evaluate_witness_quorum([a, b], **kwargs)
    r2 = evaluate_witness_quorum([b, a], **kwargs)
    assert r1.satisfied and r2.satisfied
    assert r1.witness_set_hash == r2.witness_set_hash
    assert r1.accepted_witness_ids == r2.accepted_witness_ids


def test_agent_cannot_sign_witness_statement(witness_keys, now):
    policy = WitnessPolicy()
    with pytest.raises(WitnessIssuerNotAuthorizedError):
        sign_witness_statement(
            statement_id="bad",
            manifest_hash=_MANIFEST_HASH,
            witness_policy_hash=policy.policy_hash(),
            observed_after_state_digest=_DIGEST,
            matched_expected=True,
            witness=_principal("agent-w", PrincipalType.AGENT),
            signing_key=witness_keys["w1"],
            expires_at=now + timedelta(hours=1),
            nonce="n",
            clock=FixedClock(now),
        )


def test_digest_mismatch_rejected(witness_keys, keyring, actor, subject, now):
    policy = WitnessPolicy(required_witnesses=1)
    stmt = _stmt(witness_keys, "w1", now=now, policy=policy, digest=_OTHER_DIGEST)
    result = evaluate_witness_quorum(
        [stmt],
        policy,
        manifest_hash=_MANIFEST_HASH,
        expected_after_state_digest=_DIGEST,
        actor=actor,
        subject=subject,
        keyring=keyring,
        now=now,
    )
    assert not result.satisfied
    assert any("digest" in r for r in result.rejection_reasons)


def test_actor_cannot_witness_own_effect(witness_keys, keyring, subject, now):
    policy = WitnessPolicy(required_witnesses=1)
    actor = _principal("w1")  # same id as witness
    stmt = _stmt(witness_keys, "w1", now=now, policy=policy)
    result = evaluate_witness_quorum(
        [stmt],
        policy,
        manifest_hash=_MANIFEST_HASH,
        expected_after_state_digest=_DIGEST,
        actor=actor,
        subject=subject,
        keyring=keyring,
        now=now,
    )
    assert not result.satisfied


def test_expired_statement_rejected(witness_keys, keyring, actor, subject, now):
    policy = WitnessPolicy(required_witnesses=1)
    stmt = _stmt(witness_keys, "w1", now=now, policy=policy, ttl=1)
    later = now + timedelta(seconds=10)
    result = evaluate_witness_quorum(
        [stmt],
        policy,
        manifest_hash=_MANIFEST_HASH,
        expected_after_state_digest=_DIGEST,
        actor=actor,
        subject=subject,
        keyring=keyring,
        now=later,
    )
    assert not result.satisfied
    assert any("expired" in r for r in result.rejection_reasons)


def test_batch_too_large_fails_closed(witness_keys, keyring, actor, subject, now):
    policy = WitnessPolicy(required_witnesses=1, max_statements_considered=1)
    stmts = [
        _stmt(witness_keys, "w1", now=now, policy=policy),
        _stmt(witness_keys, "w2", now=now, policy=policy),
    ]
    with pytest.raises(WitnessBatchTooLargeError):
        evaluate_witness_quorum(
            stmts,
            policy,
            manifest_hash=_MANIFEST_HASH,
            expected_after_state_digest=_DIGEST,
            actor=actor,
            subject=subject,
            keyring=keyring,
            now=now,
        )


def test_assert_raises_when_unsatisfied(witness_keys, keyring, actor, subject, now):
    policy = WitnessPolicy(required_witnesses=2)
    stmt = _stmt(witness_keys, "w1", now=now, policy=policy)
    with pytest.raises(WitnessQuorumNotMetError):
        assert_witness_quorum(
            [stmt],
            policy,
            manifest_hash=_MANIFEST_HASH,
            expected_after_state_digest=_DIGEST,
            actor=actor,
            subject=subject,
            keyring=keyring,
            now=now,
        )


def test_matched_expected_required(witness_keys, keyring, actor, subject, now):
    policy = WitnessPolicy(required_witnesses=1, require_matched_expected=True)
    stmt = _stmt(witness_keys, "w1", now=now, policy=policy, matched=False)
    result = evaluate_witness_quorum(
        [stmt],
        policy,
        manifest_hash=_MANIFEST_HASH,
        expected_after_state_digest=_DIGEST,
        actor=actor,
        subject=subject,
        keyring=keyring,
        now=now,
    )
    assert not result.satisfied


def test_policy_hash_mismatch_rejected(witness_keys, keyring, actor, subject, now):
    signed_policy = WitnessPolicy(required_witnesses=1, policy_id="a")
    eval_policy = WitnessPolicy(required_witnesses=1, policy_id="b")
    stmt = _stmt(witness_keys, "w1", now=now, policy=signed_policy)
    result = evaluate_witness_quorum(
        [stmt],
        eval_policy,
        manifest_hash=_MANIFEST_HASH,
        expected_after_state_digest=_DIGEST,
        actor=actor,
        subject=subject,
        keyring=keyring,
        now=now,
    )
    assert not result.satisfied
    assert any("witness_policy_hash" in r for r in result.rejection_reasons)


def test_later_statement_wins_per_witness(witness_keys, keyring, actor, subject, now):
    policy = WitnessPolicy(required_witnesses=1)
    early = _stmt(
        witness_keys, "w1", now=now, policy=policy, digest=_OTHER_DIGEST, statement_id="early"
    )
    late = _stmt(
        witness_keys,
        "w1",
        now=now + timedelta(seconds=5),
        policy=policy,
        digest=_DIGEST,
        statement_id="late",
    )
    result = evaluate_witness_quorum(
        [early, late],
        policy,
        manifest_hash=_MANIFEST_HASH,
        expected_after_state_digest=_DIGEST,
        actor=actor,
        subject=subject,
        keyring=keyring,
        now=now + timedelta(seconds=5),
    )
    # early mismatches digest so only late survives; still one witness
    assert result.satisfied
