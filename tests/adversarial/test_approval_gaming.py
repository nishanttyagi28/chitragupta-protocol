"""Adversarial tests for multi-party approval: attempts to game quorum
via replay, identity collision, self-approval, or vote revocation.
"""

from __future__ import annotations

from datetime import timedelta

from karmasakshi.approval import ApprovalPolicy, evaluate_quorum, sign_approval_statement
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType

_MANIFEST_HASH = "sha256:" + "1" * 64
_BUNDLE_HASH = "sha256:" + "2" * 64


def _principal(pid, ptype=PrincipalType.HUMAN):
    return Principal(principal_id=pid, principal_type=ptype)


def _sign(key, name, decision, *, now, offset_seconds=0, statement_id=None):
    return sign_approval_statement(
        statement_id=statement_id or f"stmt-{name}-{decision}-{offset_seconds}",
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        approver=_principal(name),
        decision=decision,
        signing_key=key,
        expires_at=now + timedelta(days=1),
        nonce=f"nonce-{name}-{offset_seconds}",
        clock=FixedClock(now + timedelta(seconds=offset_seconds)),
    )


def test_replaying_a_satisfied_approval_set_against_a_different_manifest_fails(now):
    key = generate_signing_key("alice-key")
    keyring = Keyring([key.verification_key()])
    stmt = _sign(key, "alice", "approve", now=now)
    policy = ApprovalPolicy(required_approvals=1)

    other_manifest = "sha256:" + "9" * 64
    result = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=other_manifest,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=keyring,
        proposer=_principal("proposer", PrincipalType.AGENT),
        subject=_principal("executor", PrincipalType.AGENT),
        now=now,
    )
    assert result.satisfied is False


def test_two_identical_principal_ids_from_different_keys_still_count_once(now):
    """Even if two different real signing keys both claim to be
    principal_id 'alice' (an identity collision -- e.g. a compromised or
    misconfigured second key), the quorum only counts one approval from
    that identity, not two, so an attacker cannot inflate the count by
    minting extra keys under an already-approving identity."""
    key_a = generate_signing_key("alice-key-a")
    key_b = generate_signing_key("alice-key-b")
    keyring = Keyring([key_a.verification_key(), key_b.verification_key()])
    stmt_a = _sign(key_a, "alice", "approve", now=now, offset_seconds=0, statement_id="s1")
    stmt_b = _sign(key_b, "alice", "approve", now=now, offset_seconds=1, statement_id="s2")
    policy = ApprovalPolicy(required_approvals=2)

    result = evaluate_quorum(
        (stmt_a, stmt_b),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=keyring,
        proposer=_principal("proposer", PrincipalType.AGENT),
        subject=_principal("executor", PrincipalType.AGENT),
        now=now,
    )
    assert result.satisfied is False
    assert result.approving_count == 1


def test_a_later_dissent_overrides_an_earlier_approval_from_the_same_approver(now):
    """An approver who changes their mind (signs a later dissent after an
    earlier approval) has their vote correctly counted as dissent, not
    approval -- the most recent signed statement per approver is
    authoritative, so an attacker cannot 'lock in' a stale approval after
    the approver has withdrawn it."""
    key = generate_signing_key("alice-key")
    keyring = Keyring([key.verification_key()])
    approve_first = _sign(key, "alice", "approve", now=now, offset_seconds=0, statement_id="s1")
    dissent_later = _sign(key, "alice", "dissent", now=now, offset_seconds=10, statement_id="s2")
    policy = ApprovalPolicy(required_approvals=1, veto_on_any_dissent=True)

    result = evaluate_quorum(
        (approve_first, dissent_later),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=keyring,
        proposer=_principal("proposer", PrincipalType.AGENT),
        subject=_principal("executor", PrincipalType.AGENT),
        now=now,
    )
    assert result.satisfied is False
    assert result.approving_count == 0
    assert result.dissenting_principal_ids == ("alice",)
    # Presenting the two statements in the opposite order must not change
    # the outcome -- the later signed_at always wins, not input order.
    result_reordered = evaluate_quorum(
        (dissent_later, approve_first),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=keyring,
        proposer=_principal("proposer", PrincipalType.AGENT),
        subject=_principal("executor", PrincipalType.AGENT),
        now=now,
    )
    assert result_reordered.satisfied is False
    assert result_reordered.dissenting_principal_ids == ("alice",)


def test_stale_earlier_approval_cannot_supersede_a_later_dissent_by_replay(now):
    """An attacker who captured an old (still-unexpired) approval
    statement cannot resurrect it to override a later dissent by simply
    resubmitting it -- the freshness tie-break is by signed_at, not by
    submission order, so replaying the old approval later doesn't help."""
    key = generate_signing_key("alice-key")
    keyring = Keyring([key.verification_key()])
    approve_first = _sign(key, "alice", "approve", now=now, offset_seconds=0, statement_id="s1")
    dissent_later = _sign(key, "alice", "dissent", now=now, offset_seconds=10, statement_id="s2")
    policy = ApprovalPolicy(required_approvals=1, veto_on_any_dissent=True)

    # Attacker resubmits the stale approval "after" the dissent in wall-clock
    # submission time, but its signed_at is still earlier.
    result = evaluate_quorum(
        (dissent_later, approve_first, approve_first),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=keyring,
        proposer=_principal("proposer", PrincipalType.AGENT),
        subject=_principal("executor", PrincipalType.AGENT),
        now=now,
    )
    assert result.satisfied is False
    assert result.dissenting_principal_ids == ("alice",)


def test_quorum_cannot_be_satisfied_by_statements_from_only_forbidden_identities(now):
    """proposer + subject exclusion together must not leave an exploitable
    gap: if every submitted statement is from an excluded identity,
    quorum is never met no matter how many are submitted."""
    proposer = _principal("proposer-1")
    subject = _principal("executor-1")
    key_p = generate_signing_key("proposer-key")
    key_s = generate_signing_key("subject-key")
    keyring = Keyring([key_p.verification_key(), key_s.verification_key()])

    stmt_proposer = sign_approval_statement(
        statement_id="s1",
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        approver=proposer,
        decision="approve",
        signing_key=key_p,
        expires_at=now + timedelta(days=1),
        nonce="n1",
        clock=FixedClock(now),
    )
    stmt_subject = sign_approval_statement(
        statement_id="s2",
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        approver=subject,
        decision="approve",
        signing_key=key_s,
        expires_at=now + timedelta(days=1),
        nonce="n2",
        clock=FixedClock(now),
    )
    policy = ApprovalPolicy(required_approvals=1)
    result = evaluate_quorum(
        (stmt_proposer, stmt_subject),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False
    assert result.approving_count == 0
    assert len(result.rejected) == 2


def test_forged_role_claim_is_trusted_only_from_a_validly_signed_statement(now):
    """A role claim is part of the signed payload -- an attacker cannot
    change a statement's declared role without invalidating its
    signature (documented limitation: roles are self-asserted by the
    signer, not checked against an external directory, but they cannot
    be tampered with post-signature)."""
    key = generate_signing_key("alice-key")
    keyring = Keyring([key.verification_key()])
    stmt = _sign(key, "alice", "approve", now=now, statement_id="s1")
    tampered = stmt.model_copy(update={"role": "finance"})
    policy = ApprovalPolicy(required_approvals=1, required_roles=("finance",))

    result = evaluate_quorum(
        (tampered,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=keyring,
        proposer=_principal("proposer", PrincipalType.AGENT),
        subject=_principal("executor", PrincipalType.AGENT),
        now=now,
    )
    assert result.satisfied is False
    assert any("signature" in reason.lower() for _, reason in result.rejected)
