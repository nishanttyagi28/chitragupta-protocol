"""Builds an :class:`ActionPassport` from the artifacts an engine run
produces: the sealed manifest, the grant (if any), the commit/outcome/
compensation results (if the lifecycle reached that far), and the audit
journal.
"""

from __future__ import annotations

from karmasakshi.adapters.base import CommitResult, CompensationResult, OutcomeProof
from karmasakshi.audit.journal import AuditJournal
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.errors import KarmaSakshiError
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.grants.verifier import verify_grant_signature
from karmasakshi.intelligence.model import EffectAssessment
from karmasakshi.passports.model import ActionPassport, PassportVerificationStatus
from karmasakshi.stores.base import GrantStore


def build_passport(
    *,
    sealed: SealedManifest,
    keyring: Keyring,
    audit: AuditJournal,
    lifecycle_state: str,
    grant: ExecutionGrant | None = None,
    grant_store: GrantStore | None = None,
    commit_result: CommitResult | None = None,
    outcome_proof: OutcomeProof | None = None,
    compensation_result: CompensationResult | None = None,
    assessment: EffectAssessment | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> ActionPassport:
    manifest = sealed.manifest

    seal_verified = True
    seal_detail: str | None = None
    try:
        sealed.verify_integrity()
    except KarmaSakshiError as exc:
        seal_verified = False
        seal_detail = str(exc)

    grant_verified = True
    if grant is not None:
        try:
            verify_grant_signature(grant, keyring)
        except KarmaSakshiError as exc:
            grant_verified = False
            seal_detail = (seal_detail + "; " if seal_detail else "") + str(exc)

    audit_chain_verified = True
    try:
        audit.verify_chain()
    except KarmaSakshiError as exc:
        audit_chain_verified = False
        seal_detail = (seal_detail + "; " if seal_detail else "") + str(exc)

    was_revoked = False
    if grant is not None and grant_store is not None:
        was_revoked = grant_store.is_revoked(grant.grant_id)

    return ActionPassport(
        generated_at=clock.now(),
        manifest_id=manifest.manifest_id,
        manifest_hash=sealed.seal.manifest_hash,
        effect_type=manifest.effect_type,
        actor=manifest.actor,
        principal=manifest.principal,
        target_resource=manifest.target_resource,
        proposed_parameters=manifest.parameters,
        risk=manifest.risk,
        reversibility=manifest.reversibility,
        grant_id=grant.grant_id if grant is not None else None,
        authorized_by=grant.issuer if grant is not None else None,
        authorization_valid_from=grant.not_before if grant is not None else None,
        authorization_valid_until=grant.expires_at if grant is not None else None,
        authorization_policy_bundle_hash=grant.policy_bundle_hash if grant is not None else None,
        was_revoked=was_revoked,
        commit_attempted=commit_result is not None,
        commit_success=commit_result.success if commit_result is not None else None,
        provider_reference=commit_result.provider_reference if commit_result is not None else None,
        commit_detail=commit_result.detail if commit_result is not None else None,
        observed_matched_expected=(
            outcome_proof.matched_expected if outcome_proof is not None else None
        ),
        observed_after_state_digest=(
            outcome_proof.observed_after_state_digest if outcome_proof is not None else None
        ),
        observation_detail=outcome_proof.detail if outcome_proof is not None else None,
        compensation_attempted=(
            compensation_result.attempted if compensation_result is not None else None
        ),
        compensation_succeeded=(
            compensation_result.succeeded if compensation_result is not None else None
        ),
        compensation_reason=(
            compensation_result.reason if compensation_result is not None else None
        ),
        assessment_id=assessment.assessment_id if assessment is not None else None,
        assessment_score=assessment.score if assessment is not None else None,
        assessment_risk_level=assessment.risk_level.value if assessment is not None else None,
        assessment_recommendation=(
            assessment.recommendation.value if assessment is not None else None
        ),
        assessment_policy_id=assessment.policy_id if assessment is not None else None,
        assessment_policy_hash=assessment.policy_hash if assessment is not None else None,
        assessment_required_human_approvals=(
            assessment.required_human_approvals if assessment is not None else None
        ),
        assessment_explanation=assessment.explanation if assessment is not None else None,
        lifecycle_state=lifecycle_state,
        verification=PassportVerificationStatus(
            seal_verified=seal_verified,
            grant_verified=grant_verified,
            audit_chain_verified=audit_chain_verified,
            detail=seal_detail,
        ),
    )


__all__ = ["build_passport"]
