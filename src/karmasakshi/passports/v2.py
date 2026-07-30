"""Action Passport V2 (extreme-v2 Phase 23).

A versioned passport format distinct from the v1 :class:`ActionPassport`.
V2 adds an explicit ``passport_format``, a derived ``outcome_status``, and
a deterministic content hash for offline verification — without claiming
new cryptographic algorithms.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import ReversibilityClassification, RiskClassification
from karmasakshi.domain.manifest import ParameterValue
from karmasakshi.errors import SchemaVersionError
from karmasakshi.passports.model import ActionPassport, PassportVerificationStatus

PASSPORT_FORMAT_V2: Literal["action_passport.v2"] = "action_passport.v2"
PASSPORT_SCHEMA_V2 = "2.0"


class OutcomeStatus(str, Enum):
    """Honest high-level outcome classification for Passport V2."""

    AUTHORIZED_NOT_COMMITTED = "authorized_not_committed"
    COMMITTED_UNVERIFIED = "committed_unverified"
    VERIFIED_MATCH = "verified_match"
    VERIFIED_MISMATCH = "verified_mismatch"
    AMBIGUOUS = "ambiguous"
    COMPENSATION_ATTEMPTED = "compensation_attempted"
    COMPENSATION_VERIFIED = "compensation_verified"
    FAILED = "failed"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


def derive_outcome_status(passport: ActionPassport) -> OutcomeStatus:
    """Deterministic mapping from v1 passport facts to V2 outcome_status."""
    state = (passport.lifecycle_state or "").lower()
    if passport.was_revoked or state == "revoked":
        return OutcomeStatus.REVOKED
    # A later, separately-authorized compensation outcome takes priority
    # over the original effect's own verification -- it is a temporally
    # later fact about the same manifest.
    if passport.compensation_passport_status == "verified" or (
        passport.compensation_succeeded is True and passport.compensation_attempted is True
    ):
        return OutcomeStatus.COMPENSATION_VERIFIED
    if passport.compensation_attempted is True:
        return OutcomeStatus.COMPENSATION_ATTEMPTED
    # RA-004: an independent post-commit observation is the strongest
    # available signal -- a commit response is never treated as proof on
    # its own (see the Gateway's /verify and /recover routes), so a
    # *matched* proof must outrank both a stale terminal "failed" lifecycle
    # label and free-text "ambiguous" commit-detail sniffing below. This is
    # what makes the Gateway read model's verification_status and this
    # Passport agree once ambiguous-outcome recovery has actually
    # confirmed what happened, instead of the Passport reporting FAILED
    # while the read model reports verified_match for the same manifest.
    if passport.observed_matched_expected is True:
        return OutcomeStatus.VERIFIED_MATCH
    if passport.observed_matched_expected is False:
        return OutcomeStatus.VERIFIED_MISMATCH
    if state == "failed":
        return OutcomeStatus.FAILED
    if passport.commit_detail and "ambiguous" in passport.commit_detail.lower():
        return OutcomeStatus.AMBIGUOUS
    if passport.commit_success is True:
        return OutcomeStatus.COMMITTED_UNVERIFIED
    if passport.grant_id is not None and not passport.commit_attempted:
        return OutcomeStatus.AUTHORIZED_NOT_COMMITTED
    if passport.commit_success is False:
        return OutcomeStatus.FAILED
    return OutcomeStatus.UNKNOWN


class ActionPassportV2(BaseModel):
    """Versioned Action Passport (schema 2.0).

    Carries the same structured facts as v1 plus explicit format/outcome
    fields. ``passport_hash`` binds the deterministic payload (excluding
    ``generated_at``).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    passport_format: Literal["action_passport.v2"] = PASSPORT_FORMAT_V2
    schema_version: str = PASSPORT_SCHEMA_V2
    generated_at: datetime
    passport_hash: str

    # Core identity (same as v1)
    manifest_id: str
    manifest_hash: str
    effect_type: str
    actor: Principal
    principal: Principal
    target_resource: str
    proposed_parameters: dict[str, ParameterValue]
    risk: RiskClassification
    reversibility: ReversibilityClassification

    grant_id: str | None = None
    authorized_by: Principal | None = None
    authorization_valid_from: datetime | None = None
    authorization_valid_until: datetime | None = None
    authorization_policy_bundle_hash: str | None = None
    authorization_approval_set_hash: str | None = None
    authorization_decision_envelope_hash: str | None = None
    authorization_causal_graph_hash: str | None = None
    was_revoked: bool = False

    role_participation: dict[str, str] | None = None
    causal_graph_id: str | None = None
    causal_graph_hash: str | None = None
    causal_ancestor_manifest_hashes: tuple[str, ...] = ()
    causal_graph_verified: bool | None = None

    commit_attempted: bool = False
    commit_success: bool | None = None
    provider_reference: str | None = None
    commit_detail: str | None = None

    observed_matched_expected: bool | None = None
    observed_after_state_digest: str | None = None
    observation_detail: str | None = None

    witness_set_hash: str | None = None
    witness_policy_hash: str | None = None
    witness_quorum_satisfied: bool | None = None
    accepted_witness_ids: tuple[str, ...] = ()

    evidence_set_hash: str | None = None
    evidence_policy_hash: str | None = None
    evidence_acceptable: bool | None = None
    evidence_strongest_kind: str | None = None

    compensation_attempted: bool | None = None
    compensation_succeeded: bool | None = None
    compensation_reason: str | None = None
    compensation_manifest_hash: str | None = None
    compensation_passport_status: str | None = None

    assessment_id: str | None = None
    assessment_score: int | None = None
    assessment_risk_level: str | None = None
    assessment_recommendation: str | None = None
    assessment_policy_id: str | None = None
    assessment_policy_hash: str | None = None
    assessment_required_human_approvals: int | None = None
    assessment_explanation: str | None = None

    lifecycle_state: str
    outcome_status: OutcomeStatus
    tenant_id: str | None = None
    verification: PassportVerificationStatus

    @field_validator("schema_version")
    @classmethod
    def _validate_schema(cls, v: str) -> str:
        if v != PASSPORT_SCHEMA_V2:
            raise SchemaVersionError(
                f"ActionPassportV2 requires schema_version {PASSPORT_SCHEMA_V2!r}, got {v!r}"
            )
        return v

    def deterministic_payload(self) -> dict[str, object]:
        """Canonical fields excluding ``generated_at`` (per-call timestamp)."""
        data = self.model_dump(mode="json")
        data.pop("generated_at", None)
        data.pop("passport_hash", None)
        return data

    def compute_passport_hash(self) -> str:
        return canonical_hash(self.deterministic_payload())

    def verify_passport_hash(self) -> None:
        expected = self.compute_passport_hash()
        if expected != self.passport_hash:
            from karmasakshi.errors import ManifestTamperedError

            raise ManifestTamperedError(
                f"ActionPassportV2 passport_hash mismatch: expected {expected}, "
                f"got {self.passport_hash}"
            )


def upgrade_passport_v1_to_v2(
    passport: ActionPassport,
    *,
    tenant_id: str | None = None,
) -> ActionPassportV2:
    """Lift a v1 Action Passport into V2 with derived outcome_status."""
    outcome = derive_outcome_status(passport)
    draft = ActionPassportV2(
        generated_at=passport.generated_at,
        passport_hash="sha256:" + ("0" * 64),  # placeholder; replaced below
        manifest_id=passport.manifest_id,
        manifest_hash=passport.manifest_hash,
        effect_type=passport.effect_type,
        actor=passport.actor,
        principal=passport.principal,
        target_resource=passport.target_resource,
        proposed_parameters=passport.proposed_parameters,
        risk=passport.risk,
        reversibility=passport.reversibility,
        grant_id=passport.grant_id,
        authorized_by=passport.authorized_by,
        authorization_valid_from=passport.authorization_valid_from,
        authorization_valid_until=passport.authorization_valid_until,
        authorization_policy_bundle_hash=passport.authorization_policy_bundle_hash,
        authorization_approval_set_hash=passport.authorization_approval_set_hash,
        authorization_decision_envelope_hash=passport.authorization_decision_envelope_hash,
        authorization_causal_graph_hash=passport.authorization_causal_graph_hash,
        was_revoked=passport.was_revoked,
        role_participation=passport.role_participation,
        causal_graph_id=passport.causal_graph_id,
        causal_graph_hash=passport.causal_graph_hash,
        causal_ancestor_manifest_hashes=passport.causal_ancestor_manifest_hashes,
        causal_graph_verified=passport.causal_graph_verified,
        commit_attempted=passport.commit_attempted,
        commit_success=passport.commit_success,
        provider_reference=passport.provider_reference,
        commit_detail=passport.commit_detail,
        observed_matched_expected=passport.observed_matched_expected,
        observed_after_state_digest=passport.observed_after_state_digest,
        observation_detail=passport.observation_detail,
        witness_set_hash=passport.witness_set_hash,
        witness_policy_hash=passport.witness_policy_hash,
        witness_quorum_satisfied=passport.witness_quorum_satisfied,
        accepted_witness_ids=passport.accepted_witness_ids,
        evidence_set_hash=passport.evidence_set_hash,
        evidence_policy_hash=passport.evidence_policy_hash,
        evidence_acceptable=passport.evidence_acceptable,
        evidence_strongest_kind=passport.evidence_strongest_kind,
        compensation_attempted=passport.compensation_attempted,
        compensation_succeeded=passport.compensation_succeeded,
        compensation_reason=passport.compensation_reason,
        compensation_manifest_hash=passport.compensation_manifest_hash,
        compensation_passport_status=passport.compensation_passport_status,
        assessment_id=passport.assessment_id,
        assessment_score=passport.assessment_score,
        assessment_risk_level=passport.assessment_risk_level,
        assessment_recommendation=passport.assessment_recommendation,
        assessment_policy_id=passport.assessment_policy_id,
        assessment_policy_hash=passport.assessment_policy_hash,
        assessment_required_human_approvals=passport.assessment_required_human_approvals,
        assessment_explanation=passport.assessment_explanation,
        lifecycle_state=passport.lifecycle_state,
        outcome_status=outcome,
        tenant_id=tenant_id,
        verification=passport.verification,
    )
    return draft.model_copy(update={"passport_hash": draft.compute_passport_hash()})


__all__ = [
    "PASSPORT_FORMAT_V2",
    "PASSPORT_SCHEMA_V2",
    "ActionPassportV2",
    "OutcomeStatus",
    "derive_outcome_status",
    "upgrade_passport_v1_to_v2",
]
