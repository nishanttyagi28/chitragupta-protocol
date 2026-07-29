"""Sign and verify independent witness statements."""

from __future__ import annotations

from datetime import datetime

from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey, assert_supported_algorithm
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import (
    InvalidSignatureError,
    WitnessExpiredError,
    WitnessIssuerNotAuthorizedError,
)
from karmasakshi.protocol.versioning import assert_supported_schema_version
from karmasakshi.witness.model import WitnessStatement


def sign_witness_statement(
    *,
    statement_id: str,
    manifest_hash: str,
    witness_policy_hash: str,
    observed_after_state_digest: str,
    matched_expected: bool,
    witness: Principal,
    signing_key: SigningKey,
    expires_at: datetime,
    nonce: str,
    clock: Clock = SYSTEM_CLOCK,
) -> WitnessStatement:
    if witness.principal_type == PrincipalType.AGENT:
        raise WitnessIssuerNotAuthorizedError(
            "an agent principal cannot sign a witness statement; "
            "witnessing must come from a human or service principal"
        )
    unsigned = WitnessStatement(
        statement_id=statement_id,
        manifest_hash=manifest_hash,
        witness_policy_hash=witness_policy_hash,
        observed_after_state_digest=observed_after_state_digest,
        matched_expected=matched_expected,
        witness=witness,
        signed_at=clock.now(),
        expires_at=expires_at,
        nonce=nonce,
        key_id=signing_key.key_id,
        algorithm=signing_key.algorithm,
        signature=None,
    )
    signature = signing_key.sign(unsigned.canonical_hash().encode("utf-8"))
    return unsigned.model_copy(update={"signature": signature})


def verify_witness_statement_signature(statement: WitnessStatement, keyring: Keyring) -> None:
    assert_supported_schema_version(statement.schema_version)
    assert_supported_algorithm(statement.algorithm)
    if statement.signature is None:
        raise InvalidSignatureError(f"witness statement {statement.statement_id} is unsigned")
    keyring.verify(
        statement.key_id, statement.canonical_hash().encode("utf-8"), statement.signature
    )


def verify_witness_statement_time_window(statement: WitnessStatement, now: datetime) -> None:
    if now > statement.expires_at:
        raise WitnessExpiredError(
            f"witness statement {statement.statement_id} expired at "
            f"{statement.expires_at.isoformat()}"
        )


__all__ = [
    "sign_witness_statement",
    "verify_witness_statement_signature",
    "verify_witness_statement_time_window",
]
