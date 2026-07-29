"""Extra coverage for witness model validators and signing edge cases."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import InvalidSignatureError, WitnessExpiredError
from karmasakshi.witness.model import WitnessPolicy, WitnessStatement
from karmasakshi.witness.signing import (
    sign_witness_statement,
    verify_witness_statement_signature,
    verify_witness_statement_time_window,
)


def test_witness_policy_validation_bounds():
    with pytest.raises(ValidationError):
        WitnessPolicy(required_witnesses=0)
    with pytest.raises(ValidationError):
        WitnessPolicy(required_witnesses=17)
    with pytest.raises(ValidationError):
        WitnessPolicy(max_statements_considered=0)
    with pytest.raises(ValidationError):
        WitnessPolicy(policy_id="")
    with pytest.raises(ValidationError):
        WitnessPolicy(policy_version="1")


def test_witness_statement_rejects_bad_hashes_and_window(now):
    base = {
        "statement_id": "s1",
        "manifest_hash": "sha256:" + "a" * 64,
        "witness_policy_hash": "sha256:" + "b" * 64,
        "observed_after_state_digest": "d",
        "matched_expected": True,
        "witness": Principal(principal_id="w", principal_type=PrincipalType.HUMAN),
        "signed_at": now,
        "expires_at": now + timedelta(hours=1),
        "nonce": "n",
        "key_id": "k",
    }
    WitnessStatement(**base)
    with pytest.raises(ValidationError):
        WitnessStatement(**{**base, "manifest_hash": "bad"})
    with pytest.raises(ValidationError):
        WitnessStatement(**{**base, "witness_policy_hash": "sha256:short"})
    with pytest.raises(ValidationError):
        WitnessStatement(**{**base, "expires_at": now})
    with pytest.raises(ValidationError):
        WitnessStatement(**{**base, "statement_id": ""})
    with pytest.raises(ValidationError):
        WitnessStatement(**{**base, "observed_after_state_digest": ""})


def test_unsigned_and_expired_verification(now):
    key = generate_signing_key("k1")
    policy = WitnessPolicy()
    stmt = sign_witness_statement(
        statement_id="s1",
        manifest_hash="sha256:" + "a" * 64,
        witness_policy_hash=policy.policy_hash(),
        observed_after_state_digest="d",
        matched_expected=True,
        witness=Principal(principal_id="w", principal_type=PrincipalType.HUMAN),
        signing_key=key,
        expires_at=now + timedelta(seconds=1),
        nonce="n",
        clock=FixedClock(now),
    )
    keyring = Keyring([key.verification_key()])
    verify_witness_statement_signature(stmt, keyring)
    unsigned = stmt.model_copy(update={"signature": None})
    with pytest.raises(InvalidSignatureError):
        verify_witness_statement_signature(unsigned, keyring)
    with pytest.raises(WitnessExpiredError):
        verify_witness_statement_time_window(stmt, now + timedelta(seconds=10))
