"""Typed Gateway read models for the Milestone A refund Control Center.

These models are shared by the HTTP API and both SDK clients.  Keeping
them in the Gateway layer prevents the server and UI-facing SDK from
silently drifting apart as the read surface evolves.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from karmasakshi.audit.events import AuditEvent
from karmasakshi.intelligence.model import RiskSignal


class RefundAssessmentOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: int
    risk_level: str
    signals: tuple[RiskSignal, ...] = ()
    recommendation: str
    required_human_approvals: int
    required_service_approvals: int = 0
    cooling_off_period_seconds: int = 0
    required_witness_quorum: int = 0
    required_verification_strength: str = "standard"
    policy_id: str
    policy_version: str
    policy_hash: str
    explanation: str


class RefundEffectView(BaseModel):
    """Exact, manifest-bound before/expected-after values shown to an approver."""

    model_config = ConfigDict(extra="forbid")

    source_account: str
    beneficiary: str
    amount_minor_units: int
    fee_minor_units: int
    currency: str
    reference: str
    idempotency_key: str
    source_balance_before_minor_units: int
    source_balance_expected_after_minor_units: int
    beneficiary_credit_before_minor_units: int = 0
    beneficiary_credit_expected_after_minor_units: int
    observed_after_state_digest: str | None = None


class RefundPolicyDecisionOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation: str
    policy_id: str
    policy_version: str
    policy_hash: str
    active_policy_bundle_id: str | None = None
    bound_policy_bundle_hash: str | None = None
    required_human_approvals: int
    completed_human_approvals: int
    required_service_approvals: int
    cooling_off_period_seconds: int
    required_witness_quorum: int
    required_verification_strength: str


class RefundSummaryOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_id: str
    manifest_hash: str
    created_at: datetime
    beneficiary: str
    amount_minor_units: int
    currency: str
    reference: str
    lifecycle_state: str
    decision_status: str
    risk_score: int
    risk_level: str
    recommendation: str
    ambiguous: bool
    verification_status: str


class RefundDetailOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_id: str
    manifest_id: str
    manifest_hash: str
    actor_id: str
    requested_by: str
    created_at: datetime
    expires_at: datetime
    lifecycle_state: str
    decision_status: str
    denied_by: str | None = None
    denial_reason: str | None = None
    can_approve: bool
    can_deny: bool
    grant_id: str | None = None
    authorized_by: str | None = None
    effect: RefundEffectView
    assessment: RefundAssessmentOut
    policy_decision: RefundPolicyDecisionOut
    commit_attempted: bool
    commit_success: bool | None = None
    provider_reference: str | None = None
    commit_detail: str | None = None
    ambiguous: bool
    verification_status: str
    verification_matched_expected: bool | None = None
    verification_detail: str | None = None
    timeline: list[AuditEvent] = Field(default_factory=list)


class RefundListOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refunds: list[RefundSummaryOut]


class RefundDenyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=200)


class RefundDenyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_id: str
    denied: bool
    denied_by: str
    reason: str


__all__ = [
    "RefundAssessmentOut",
    "RefundDenyIn",
    "RefundDenyResult",
    "RefundDetailOut",
    "RefundEffectView",
    "RefundListOut",
    "RefundPolicyDecisionOut",
    "RefundSummaryOut",
]
