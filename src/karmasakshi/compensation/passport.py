"""Compensation Passport: a separate proof document for one compensation effect.

Never mutates an :class:`~karmasakshi.passports.model.ActionPassport`. The
original passport may only *point* at this document; compensation outcomes
live here.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from karmasakshi.adapters.base import CommitResult, CompensationResult, OutcomeProof
from karmasakshi.audit.journal import AuditJournal
from karmasakshi.compensation.manifest import (
    assert_compensation_binds_original,
    original_manifest_hash_of,
)
from karmasakshi.compensation.status import CompensationStatus
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.domain.common import Principal
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.errors import KarmaSakshiError
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.grants.verifier import verify_grant_signature
from karmasakshi.protocol.versioning import CURRENT_SCHEMA_VERSION


class CompensationPassport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    generated_at: datetime

    compensation_manifest_id: str
    compensation_manifest_hash: str
    compensation_effect_type: str
    original_manifest_id: str
    original_manifest_hash: str

    status: CompensationStatus

    grant_id: str | None = None
    authorized_by: Principal | None = None

    commit_attempted: bool = False
    commit_success: bool | None = None
    provider_reference: str | None = None
    commit_detail: str | None = None

    observed_matched_expected: bool | None = None
    observation_detail: str | None = None

    refused: bool = False
    refusal_reason: str | None = None

    seal_verified: bool
    grant_verified: bool | None = None
    audit_chain_verified: bool
    detail: str | None = None


def derive_compensation_status(
    *,
    adapter_result: CompensationResult | None = None,
    commit_result: CommitResult | None = None,
    outcome_proof: OutcomeProof | None = None,
) -> CompensationStatus:
    """Map structured facts to refused / attempted / verified.

    Verification requires an independent outcome proof with
    ``matched_expected=True``. An adapter ``succeeded=True`` alone is never
    enough for ``VERIFIED``.
    """
    if adapter_result is not None and not adapter_result.attempted:
        return CompensationStatus.REFUSED
    if outcome_proof is not None and outcome_proof.matched_expected:
        return CompensationStatus.VERIFIED
    if commit_result is not None and commit_result.success:
        return CompensationStatus.ATTEMPTED
    if adapter_result is not None and adapter_result.attempted:
        return CompensationStatus.ATTEMPTED
    return CompensationStatus.REFUSED


def build_compensation_passport(
    *,
    compensation_sealed: SealedManifest,
    original_sealed: SealedManifest,
    keyring: Keyring,
    audit: AuditJournal,
    grant: ExecutionGrant | None = None,
    commit_result: CommitResult | None = None,
    outcome_proof: OutcomeProof | None = None,
    adapter_result: CompensationResult | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> CompensationPassport:
    """Build a Compensation Passport. Does not read or write Action Passports."""
    assert_compensation_binds_original(compensation_sealed, original_sealed)
    original_hash = original_manifest_hash_of(compensation_sealed.manifest)

    seal_verified = True
    detail: str | None = None
    try:
        compensation_sealed.verify_integrity()
    except KarmaSakshiError as exc:
        seal_verified = False
        detail = str(exc)

    grant_verified: bool | None = None
    if grant is not None:
        grant_verified = True
        try:
            verify_grant_signature(grant, keyring)
        except KarmaSakshiError as exc:
            grant_verified = False
            detail = (detail + "; " if detail else "") + str(exc)

    audit_ok = True
    try:
        audit.verify_chain()
    except KarmaSakshiError as exc:
        audit_ok = False
        detail = (detail + "; " if detail else "") + str(exc)

    status = derive_compensation_status(
        adapter_result=adapter_result,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    refused = status == CompensationStatus.REFUSED

    return CompensationPassport(
        generated_at=clock.now(),
        compensation_manifest_id=compensation_sealed.manifest.manifest_id,
        compensation_manifest_hash=compensation_sealed.seal.manifest_hash,
        compensation_effect_type=compensation_sealed.manifest.effect_type,
        original_manifest_id=original_sealed.manifest.manifest_id,
        original_manifest_hash=original_hash,
        status=status,
        grant_id=grant.grant_id if grant is not None else None,
        authorized_by=grant.issuer if grant is not None else None,
        commit_attempted=commit_result is not None
        or (adapter_result is not None and adapter_result.attempted),
        commit_success=(
            commit_result.success
            if commit_result is not None
            else (adapter_result.succeeded if adapter_result is not None else None)
        ),
        provider_reference=commit_result.provider_reference if commit_result is not None else None,
        commit_detail=(
            commit_result.detail
            if commit_result is not None
            else (adapter_result.detail if adapter_result is not None else None)
        ),
        observed_matched_expected=(
            outcome_proof.matched_expected if outcome_proof is not None else None
        ),
        observation_detail=outcome_proof.detail if outcome_proof is not None else None,
        refused=refused,
        refusal_reason=(adapter_result.reason if adapter_result is not None and refused else None),
        seal_verified=seal_verified,
        grant_verified=grant_verified,
        audit_chain_verified=audit_ok,
        detail=detail,
    )


__all__ = [
    "CompensationPassport",
    "build_compensation_passport",
    "derive_compensation_status",
]
