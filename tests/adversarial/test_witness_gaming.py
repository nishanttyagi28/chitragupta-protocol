"""Adversarial tests for independent witness quorum (Phase 9)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import WitnessIssuerNotAuthorizedError
from karmasakshi.witness import WitnessPolicy, evaluate_witness_quorum, sign_witness_statement

_MH = "sha256:" + "b" * 64
_DIGEST = "ok-digest"


def _p(pid, t=PrincipalType.HUMAN):
    return Principal(principal_id=pid, principal_type=t)


def test_forged_agent_typed_statement_never_counts_even_if_signature_present(now):
    key = generate_signing_key("svc")
    policy = WitnessPolicy(required_witnesses=1)
    with pytest.raises(WitnessIssuerNotAuthorizedError):
        sign_witness_statement(
            statement_id="x",
            manifest_hash=_MH,
            witness_policy_hash=policy.policy_hash(),
            observed_after_state_digest=_DIGEST,
            matched_expected=True,
            witness=_p("bot", PrincipalType.AGENT),
            signing_key=key,
            expires_at=now + timedelta(hours=1),
            nonce="n",
            clock=FixedClock(now),
        )


def test_lowering_required_witnesses_via_policy_swap_invalidates_bound_statements(now):
    key = generate_signing_key("w")
    keyring = Keyring([key.verification_key()])
    strict = WitnessPolicy(required_witnesses=2, policy_id="strict")
    lax = WitnessPolicy(required_witnesses=1, policy_id="lax")
    stmt = sign_witness_statement(
        statement_id="s1",
        manifest_hash=_MH,
        witness_policy_hash=strict.policy_hash(),
        observed_after_state_digest=_DIGEST,
        matched_expected=True,
        witness=_p("alice"),
        signing_key=key,
        expires_at=now + timedelta(hours=1),
        nonce="n1",
        clock=FixedClock(now),
    )
    result = evaluate_witness_quorum(
        [stmt],
        lax,
        manifest_hash=_MH,
        expected_after_state_digest=_DIGEST,
        actor=_p("actor", PrincipalType.AGENT),
        subject=_p("subj", PrincipalType.AGENT),
        keyring=keyring,
        now=now,
    )
    assert not result.satisfied


def test_subject_executor_cannot_self_witness(now):
    key = generate_signing_key("w")
    keyring = Keyring([key.verification_key()])
    policy = WitnessPolicy(required_witnesses=1)
    stmt = sign_witness_statement(
        statement_id="s1",
        manifest_hash=_MH,
        witness_policy_hash=policy.policy_hash(),
        observed_after_state_digest=_DIGEST,
        matched_expected=True,
        witness=_p("executor-1"),
        signing_key=key,
        expires_at=now + timedelta(hours=1),
        nonce="n",
        clock=FixedClock(now),
    )
    result = evaluate_witness_quorum(
        [stmt],
        policy,
        manifest_hash=_MH,
        expected_after_state_digest=_DIGEST,
        actor=_p("actor", PrincipalType.AGENT),
        subject=_p("executor-1", PrincipalType.SERVICE),
        keyring=keyring,
        now=now,
    )
    assert not result.satisfied
