"""The Action Passport: a complete, honest record of one effect's lifecycle.

Deliberately excludes chain-of-thought or any free-form model reasoning --
only structured facts about what was proposed, approved, executed, and
observed (see docs/action-passports.md).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import ReversibilityClassification, RiskClassification
from karmasakshi.domain.manifest import ParameterValue
from karmasakshi.protocol.versioning import CURRENT_SCHEMA_VERSION


class PassportVerificationStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seal_verified: bool
    grant_verified: bool
    audit_chain_verified: bool
    detail: str | None = None


class ActionPassport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    generated_at: datetime

    # What was proposed / the exact approved effect
    manifest_id: str
    manifest_hash: str
    effect_type: str
    actor: Principal
    principal: Principal
    target_resource: str
    proposed_parameters: dict[str, ParameterValue]
    risk: RiskClassification
    reversibility: ReversibilityClassification

    # Who/what authorized it, and the validity window
    grant_id: str | None = None
    authorized_by: Principal | None = None
    authorization_valid_from: datetime | None = None
    authorization_valid_until: datetime | None = None
    authorization_policy_bundle_hash: str | None = None
    authorization_approval_set_hash: str | None = None
    was_revoked: bool = False

    # Separation of Duties (extreme-v2 Phase 4): which principal(s) held
    # which protocol role for this manifest, e.g. {"proposer": "user:a",
    # "approver": "user:b,user:c"} -- see docs/separation-of-duties.md.
    # None if no role assignment was recorded (e.g. authorize() was
    # called before Phase 4, or without a role_assignment).
    role_participation: dict[str, str] | None = None

    # Verifiable causal story (extreme-v2 Phase 5). None for standalone
    # effects or callers that do not supply a graph when building a passport.
    causal_graph_id: str | None = None
    causal_graph_hash: str | None = None
    causal_ancestor_manifest_hashes: tuple[str, ...] = ()
    causal_graph_verified: bool | None = None

    # What was executed
    commit_attempted: bool = False
    commit_success: bool | None = None
    provider_reference: str | None = None
    commit_detail: str | None = None

    # What external state was observed afterward
    observed_matched_expected: bool | None = None
    observed_after_state_digest: str | None = None
    observation_detail: str | None = None

    # Compensation
    compensation_attempted: bool | None = None
    compensation_succeeded: bool | None = None
    compensation_reason: str | None = None

    # Effect Intelligence assessment (advisory in this protocol version --
    # see docs/effect-intelligence.md; None if assess() was never called for
    # this manifest)
    assessment_id: str | None = None
    assessment_score: int | None = None
    assessment_risk_level: str | None = None
    assessment_recommendation: str | None = None
    assessment_policy_id: str | None = None
    assessment_policy_hash: str | None = None
    assessment_required_human_approvals: int | None = None
    assessment_explanation: str | None = None

    # Lifecycle + cryptographic verification status
    lifecycle_state: str
    verification: PassportVerificationStatus


__all__ = ["ActionPassport", "PassportVerificationStatus"]
