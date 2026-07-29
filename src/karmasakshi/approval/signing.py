"""Signing and verifying approval statements -- mirrors
``grants/issuer.py``/``grants/verifier.py``: an ``ApprovalStatement`` is
itself the signed artifact (like ``ExecutionGrant``), not wrapped in a
separate seal envelope.
"""

from __future__ import annotations

from datetime import datetime

from karmasakshi.approval.model import ApprovalStatement, Decision
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey, assert_supported_algorithm
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import (
    ApprovalExpiredError,
    ApprovalIssuerNotAuthorizedError,
    InvalidSignatureError,
)
from karmasakshi.protocol.versioning import assert_supported_schema_version


def sign_approval_statement(
    *,
    statement_id: str,
    manifest_hash: str,
    approval_policy_bundle_hash: str,
    approver: Principal,
    decision: Decision,
    signing_key: SigningKey,
    expires_at: datetime,
    nonce: str,
    role: str | None = None,
    reason: str | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> ApprovalStatement:
    """Mint and sign a new :class:`ApprovalStatement`.

    Raises :class:`ApprovalIssuerNotAuthorizedError` if ``approver`` is an
    agent principal -- an agent may never satisfy approval quorum
    (invariant #30 applied to approvals).
    """
    if approver.principal_type == PrincipalType.AGENT:
        raise ApprovalIssuerNotAuthorizedError(
            "an agent principal cannot sign an approval statement; approval must "
            "come from a human or service principal (invariant #30)"
        )
    unsigned = ApprovalStatement(
        statement_id=statement_id,
        manifest_hash=manifest_hash,
        approval_policy_bundle_hash=approval_policy_bundle_hash,
        approver=approver,
        role=role,
        decision=decision,
        reason=reason,
        signed_at=clock.now(),
        expires_at=expires_at,
        nonce=nonce,
        key_id=signing_key.key_id,
        algorithm=signing_key.algorithm,
        signature=None,
    )
    signature = signing_key.sign(unsigned.canonical_hash().encode("utf-8"))
    return unsigned.model_copy(update={"signature": signature})


def verify_approval_statement_signature(statement: ApprovalStatement, keyring: Keyring) -> None:
    """Verify schema version, algorithm, and cryptographic signature only."""
    assert_supported_schema_version(statement.schema_version)
    assert_supported_algorithm(statement.algorithm)
    if statement.signature is None:
        raise InvalidSignatureError(f"approval statement {statement.statement_id} is unsigned")
    payload_hash = statement.canonical_hash()
    keyring.verify(statement.key_id, payload_hash.encode("utf-8"), statement.signature)


def verify_approval_statement_time_window(statement: ApprovalStatement, now: datetime) -> None:
    if now > statement.expires_at:
        raise ApprovalExpiredError(
            f"approval statement {statement.statement_id} expired at "
            f"{statement.expires_at.isoformat()} (now={now.isoformat()})"
        )


def verify_approval_statement(
    statement: ApprovalStatement, keyring: Keyring, now: datetime
) -> None:
    """Full structural verification: signature, then time window."""
    verify_approval_statement_signature(statement, keyring)
    verify_approval_statement_time_window(statement, now)


__all__ = [
    "sign_approval_statement",
    "verify_approval_statement",
    "verify_approval_statement_signature",
    "verify_approval_statement_time_window",
]
