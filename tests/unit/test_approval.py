from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.approval import (
    ApprovalPolicy,
    approval_policy_from_bundle_payload,
    build_approval_policy_bundle,
    evaluate_quorum,
    sign_approval_statement,
    verify_approval_statement,
)
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import (
    ApprovalBatchTooLargeError,
    ApprovalExpiredError,
    ApprovalIssuerNotAuthorizedError,
    InvalidSignatureError,
    PolicyBundleIssuerNotAuthorizedError,
    UnknownKeyError,
)

_MANIFEST_HASH = "sha256:" + "1" * 64
_BUNDLE_HASH = "sha256:" + "2" * 64
_OTHER_MANIFEST_HASH = "sha256:" + "3" * 64


def _principal(pid, ptype=PrincipalType.HUMAN):
    return Principal(principal_id=pid, principal_type=ptype)


@pytest.fixture
def proposer():
    return _principal("proposer-1", PrincipalType.AGENT)


@pytest.fixture
def subject():
    return _principal("agent-executor-1", PrincipalType.AGENT)


@pytest.fixture
def approver_keys():
    return {name: generate_signing_key(f"key-{name}") for name in ("alice", "bob", "carol", "dave")}


@pytest.fixture
def multi_keyring(approver_keys):
    return Keyring([k.verification_key() for k in approver_keys.values()])


def _statement(
    approver_keys,
    name,
    *,
    now,
    decision="approve",
    role=None,
    ttl=3600,
    manifest_hash=_MANIFEST_HASH,
    bundle_hash=_BUNDLE_HASH,
    statement_id=None,
):
    key = approver_keys[name]
    return sign_approval_statement(
        statement_id=statement_id or f"stmt-{name}",
        manifest_hash=manifest_hash,
        approval_policy_bundle_hash=bundle_hash,
        approver=_principal(name),
        decision=decision,
        role=role,
        signing_key=key,
        expires_at=now + timedelta(seconds=ttl),
        nonce=f"nonce-{name}",
        clock=FixedClock(now),
    )


# --- ApprovalPolicy -----------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"required_approvals": 0},
        {"cooling_off_seconds": -1},
        {"max_statements_considered": 0, "required_approvals": 1},
        {"policy_version": "1"},
        {"required_roles": ("finance", "finance")},
    ],
)
def test_invalid_approval_policy_rejected(kwargs):
    with pytest.raises(ValueError):
        ApprovalPolicy(**kwargs)


def test_approval_policy_hash_deterministic_regardless_of_role_order():
    p1 = ApprovalPolicy(required_roles=("finance", "security"))
    p2 = ApprovalPolicy(required_roles=("security", "finance"))
    assert p1.policy_hash() == p2.policy_hash()


# --- policy bundle round trip --------------------------------------------------


def test_approval_policy_round_trips_through_bundle_payload(now):
    original = ApprovalPolicy(required_approvals=2, required_roles=("finance", "security"))
    bundle = build_approval_policy_bundle(
        original,
        bundle_id="b1",
        bundle_version="1.0",
        issuer=_principal("admin"),
        created_at=now,
        effective_from=now,
    )
    reconstructed = approval_policy_from_bundle_payload(bundle.payload)
    assert reconstructed.policy_hash() == original.policy_hash()


def test_approval_policy_bundle_rejects_agent_issuer(now):
    with pytest.raises(PolicyBundleIssuerNotAuthorizedError):
        build_approval_policy_bundle(
            ApprovalPolicy(),
            bundle_id="b1",
            bundle_version="1.0",
            issuer=_principal("agent-1", PrincipalType.AGENT),
            created_at=now,
            effective_from=now,
        )


# --- statement signing ----------------------------------------------------------


def test_sign_and_verify_approval_statement(approver_keys, multi_keyring, now):
    stmt = _statement(approver_keys, "alice", now=now)
    verify_approval_statement(stmt, multi_keyring, now=now)  # must not raise


def test_agent_cannot_sign_approval_statement(now):
    with pytest.raises(ApprovalIssuerNotAuthorizedError):
        sign_approval_statement(
            statement_id="s1",
            manifest_hash=_MANIFEST_HASH,
            approval_policy_bundle_hash=_BUNDLE_HASH,
            approver=_principal("agent-1", PrincipalType.AGENT),
            decision="approve",
            signing_key=generate_signing_key("k"),
            expires_at=now + timedelta(seconds=60),
            nonce="n1",
        )


def test_verify_rejects_expired_statement(approver_keys, multi_keyring, now):
    stmt = _statement(approver_keys, "alice", now=now, ttl=60)
    with pytest.raises(ApprovalExpiredError):
        verify_approval_statement(stmt, multi_keyring, now=now + timedelta(seconds=61))


def test_verify_rejects_unknown_signer(approver_keys, now):
    stmt = _statement(approver_keys, "alice", now=now)
    with pytest.raises(UnknownKeyError):
        verify_approval_statement(stmt, Keyring([]), now=now)


def test_verify_rejects_forged_signature(approver_keys, multi_keyring, now):
    stmt = _statement(approver_keys, "alice", now=now)
    attacker = generate_signing_key("attacker")
    forged = stmt.model_copy(
        update={"signature": attacker.sign(stmt.canonical_hash().encode("utf-8"))}
    )
    with pytest.raises(InvalidSignatureError):
        verify_approval_statement(forged, multi_keyring, now=now)


# --- evaluate_quorum ------------------------------------------------------------


def test_single_approval_satisfies_one_of_one(approver_keys, multi_keyring, now, proposer, subject):
    policy = ApprovalPolicy(required_approvals=1)
    stmt = _statement(approver_keys, "alice", now=now)
    result = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is True
    assert result.approving_count == 1


def test_two_of_three_not_met_with_one(approver_keys, multi_keyring, now, proposer, subject):
    policy = ApprovalPolicy(required_approvals=2)
    stmt = _statement(approver_keys, "alice", now=now)
    result = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False


def test_two_of_three_met_with_two_distinct(approver_keys, multi_keyring, now, proposer, subject):
    policy = ApprovalPolicy(required_approvals=2)
    stmts = (
        _statement(approver_keys, "alice", now=now),
        _statement(approver_keys, "bob", now=now),
    )
    result = evaluate_quorum(
        stmts,
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is True
    assert result.approving_count == 2
    assert result.approving_principal_ids == ("alice", "bob")


def test_duplicate_approver_only_counted_once(approver_keys, multi_keyring, now, proposer, subject):
    policy = ApprovalPolicy(required_approvals=2)
    stmts = (
        _statement(approver_keys, "alice", now=now, statement_id="s1"),
        _statement(approver_keys, "alice", now=now, statement_id="s2"),
    )
    result = evaluate_quorum(
        stmts,
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False
    assert result.approving_count == 1
    assert len(result.rejected) == 1


def test_role_requirement_enforced(approver_keys, multi_keyring, now, proposer, subject):
    policy = ApprovalPolicy(required_approvals=1, required_roles=("finance", "security"))
    stmt = _statement(approver_keys, "alice", now=now, role="finance")
    result = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False
    assert result.missing_roles == ("security",)


def test_role_requirement_satisfied_by_distinct_role_holders(
    approver_keys, multi_keyring, now, proposer, subject
):
    policy = ApprovalPolicy(required_approvals=1, required_roles=("finance", "security"))
    stmts = (
        _statement(approver_keys, "alice", now=now, role="finance"),
        _statement(approver_keys, "bob", now=now, role="security"),
    )
    result = evaluate_quorum(
        stmts,
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is True
    assert result.missing_roles == ()


def test_proposer_cannot_approve_own_proposal(approver_keys, multi_keyring, now, subject):
    proposer = _principal("alice")
    policy = ApprovalPolicy(required_approvals=1)
    stmt = _statement(approver_keys, "alice", now=now)
    result = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False
    assert result.rejected[0][1] == "proposer cannot approve its own proposal"


def test_subject_cannot_satisfy_quorum(approver_keys, multi_keyring, now, proposer):
    subject = _principal("alice")
    policy = ApprovalPolicy(required_approvals=1)
    stmt = _statement(approver_keys, "alice", now=now)
    result = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False


def test_agent_approver_always_rejected_even_if_policy_permissive(
    approver_keys, multi_keyring, now, proposer, subject
):
    # An agent-typed approver statement cannot be constructed via
    # sign_approval_statement (it raises), so simulate one arriving from
    # an external/legacy source via direct model construction to prove
    # evaluate_quorum independently enforces invariant #30.
    from karmasakshi.approval.model import ApprovalStatement

    key = approver_keys["alice"]
    unsigned = ApprovalStatement(
        statement_id="s1",
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        approver=_principal("agent-1", PrincipalType.AGENT),
        decision="approve",
        signed_at=now,
        expires_at=now + timedelta(seconds=60),
        nonce="n1",
        key_id=key.key_id,
        algorithm=key.algorithm,
        signature=None,
    )
    stmt = unsigned.model_copy(
        update={"signature": key.sign(unsigned.canonical_hash().encode("utf-8"))}
    )
    policy = ApprovalPolicy(required_approvals=1)
    result = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False
    assert "invariant #30" in result.rejected[0][1]


def test_dissent_vetoes_by_default(approver_keys, multi_keyring, now, proposer, subject):
    policy = ApprovalPolicy(required_approvals=1, veto_on_any_dissent=True)
    stmts = (
        _statement(approver_keys, "alice", now=now, decision="approve"),
        _statement(approver_keys, "bob", now=now, decision="dissent"),
    )
    result = evaluate_quorum(
        stmts,
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False
    assert result.dissenting_principal_ids == ("bob",)


def test_dissent_does_not_veto_when_disabled(approver_keys, multi_keyring, now, proposer, subject):
    policy = ApprovalPolicy(required_approvals=1, veto_on_any_dissent=False)
    stmts = (
        _statement(approver_keys, "alice", now=now, decision="approve"),
        _statement(approver_keys, "bob", now=now, decision="dissent"),
    )
    result = evaluate_quorum(
        stmts,
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is True


def test_wrong_manifest_hash_rejected(approver_keys, multi_keyring, now, proposer, subject):
    policy = ApprovalPolicy(required_approvals=1)
    stmt = _statement(approver_keys, "alice", now=now, manifest_hash=_OTHER_MANIFEST_HASH)
    result = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False
    assert result.rejected[0][1] == "manifest_hash mismatch"


def test_wrong_approval_policy_bundle_hash_rejected(
    approver_keys, multi_keyring, now, proposer, subject
):
    other_bundle_hash = "sha256:" + "4" * 64
    policy = ApprovalPolicy(required_approvals=1)
    stmt = _statement(approver_keys, "alice", now=now, bundle_hash=other_bundle_hash)
    result = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert result.satisfied is False
    assert result.rejected[0][1] == "approval_policy_bundle_hash mismatch"


def test_cooling_off_period_delays_satisfaction(
    approver_keys, multi_keyring, now, proposer, subject
):
    policy = ApprovalPolicy(required_approvals=1, cooling_off_seconds=300)
    stmt = _statement(approver_keys, "alice", now=now)
    too_soon = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now + timedelta(seconds=60),
    )
    assert too_soon.satisfied is False

    later = evaluate_quorum(
        (stmt,),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now + timedelta(seconds=301),
    )
    assert later.satisfied is True


def test_batch_too_large_rejected(approver_keys, multi_keyring, now, proposer, subject):
    policy = ApprovalPolicy(required_approvals=1, max_statements_considered=1)
    stmts = (
        _statement(approver_keys, "alice", now=now, statement_id="s1"),
        _statement(approver_keys, "bob", now=now, statement_id="s2"),
    )
    with pytest.raises(ApprovalBatchTooLargeError):
        evaluate_quorum(
            stmts,
            policy,
            manifest_hash=_MANIFEST_HASH,
            approval_policy_bundle_hash=_BUNDLE_HASH,
            keyring=multi_keyring,
            proposer=proposer,
            subject=subject,
            now=now,
        )


def test_approval_set_hash_stable_regardless_of_statement_order(
    approver_keys, multi_keyring, now, proposer, subject
):
    policy = ApprovalPolicy(required_approvals=2)
    a = _statement(approver_keys, "alice", now=now)
    b = _statement(approver_keys, "bob", now=now)
    r1 = evaluate_quorum(
        (a, b),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    r2 = evaluate_quorum(
        (b, a),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=multi_keyring,
        proposer=proposer,
        subject=subject,
        now=now,
    )
    assert r1.approval_set_hash == r2.approval_set_hash
    assert r1.satisfied == r2.satisfied == True  # noqa: E712
