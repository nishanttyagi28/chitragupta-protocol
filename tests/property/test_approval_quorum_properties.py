from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from karmasakshi.approval import ApprovalPolicy, evaluate_quorum, sign_approval_statement
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_MANIFEST_HASH = "sha256:" + "1" * 64
_BUNDLE_HASH = "sha256:" + "2" * 64
_PROPOSER = Principal(principal_id="proposer-1", principal_type=PrincipalType.AGENT)
_SUBJECT = Principal(principal_id="executor-1", principal_type=PrincipalType.AGENT)

_APPROVER_NAMES = [f"approver-{i}" for i in range(6)]
_KEYS = {name: generate_signing_key(f"key-{name}") for name in _APPROVER_NAMES}
_KEYRING = Keyring([k.verification_key() for k in _KEYS.values()])


def _statement(name: str, decision: str, offset_seconds: int):
    key = _KEYS[name]
    return sign_approval_statement(
        statement_id=f"stmt-{name}-{decision}-{offset_seconds}",
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        approver=Principal(principal_id=name, principal_type=PrincipalType.HUMAN),
        decision=decision,  # type: ignore[arg-type]
        signing_key=key,
        expires_at=_NOW + timedelta(days=1),
        nonce=f"nonce-{name}-{offset_seconds}",
        clock=FixedClock(_NOW + timedelta(seconds=offset_seconds)),
    )


@st.composite
def _statement_sets(draw: st.DrawFn):
    n = draw(st.integers(min_value=0, max_value=6))
    names = draw(st.permutations(_APPROVER_NAMES).map(lambda p: p[:n]))
    statements = []
    for i, name in enumerate(names):
        decision = draw(st.sampled_from(["approve", "dissent"]))
        statements.append(_statement(name, decision, offset_seconds=i))
    return tuple(statements)


@given(_statement_sets(), st.integers(min_value=1, max_value=4), st.booleans())
@settings(max_examples=150, deadline=None)
def test_quorum_verdict_independent_of_statement_order(statements, required, veto):
    policy = ApprovalPolicy(required_approvals=required, veto_on_any_dissent=veto)
    # Reversal is a sufficient order permutation for this property (not a
    # security-sensitive shuffle -- just exercising a different input order).
    shuffled = tuple(reversed(statements))

    r1 = evaluate_quorum(
        statements,
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=_KEYRING,
        proposer=_PROPOSER,
        subject=_SUBJECT,
        now=_NOW + timedelta(days=1) - timedelta(seconds=1),
    )
    r2 = evaluate_quorum(
        tuple(shuffled),
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=_KEYRING,
        proposer=_PROPOSER,
        subject=_SUBJECT,
        now=_NOW + timedelta(days=1) - timedelta(seconds=1),
    )
    assert r1.satisfied == r2.satisfied
    assert r1.approving_count == r2.approving_count
    assert r1.approving_principal_ids == r2.approving_principal_ids
    assert r1.dissenting_principal_ids == r2.dissenting_principal_ids
    assert r1.missing_roles == r2.missing_roles
    assert r1.approval_set_hash == r2.approval_set_hash


@given(_statement_sets())
@settings(max_examples=100, deadline=None)
def test_approving_count_never_exceeds_distinct_approvers(statements):
    policy = ApprovalPolicy(required_approvals=1)
    result = evaluate_quorum(
        statements,
        policy,
        manifest_hash=_MANIFEST_HASH,
        approval_policy_bundle_hash=_BUNDLE_HASH,
        keyring=_KEYRING,
        proposer=_PROPOSER,
        subject=_SUBJECT,
        now=_NOW + timedelta(days=1) - timedelta(seconds=1),
    )
    distinct_approvers = {s.approver.principal_id for s in statements}
    assert result.approving_count <= len(distinct_approvers)
    assert len(set(result.approving_principal_ids)) == len(result.approving_principal_ids)
