"""Typed response models for the Gateway HTTP API SDK (Milestone A).

Reuses the *same* pydantic models the server validates against wherever
the Gateway response body is already one of them (`ActionPassport`,
`ActionPassportV2`, `EvidencePack`, `EvidencePackVerificationResult`,
`AuditEvent`, and the org/user models in `karmasakshi.gateway.schemas`)
-- this guarantees the SDK's types cannot drift out of sync with the
server's, because they are the same class. Only the refund-journey
convenience responses (which the server returns as plain dicts, see
`karmasakshi.gateway.refunds`) get their own small models here.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from karmasakshi.gateway.refund_schemas import RefundAssessmentOut

RefundAssessment = RefundAssessmentOut


class RefundProposalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_id: str
    manifest_hash: str
    assessment: RefundAssessment


class ApprovalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str | None = None
    policy_bundle_hash: str | None = None
    completed_human_approvals: int
    required_human_approvals: int
    authorized: bool


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool
    provider_reference: str | None = None
    detail: str | None = None


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    matched_expected: bool
    detail: str | None = None


class CompensationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    compensation_manifest_id: str
    attempted: bool
    succeeded: bool
    detail: str | None = None


class PolicyActivationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    bundle_hash: str
    active: bool


class AuditVerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verified: bool


class SimulatorInjectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    armed: bool


__all__ = [
    "ApprovalResult",
    "AuditVerificationResult",
    "CompensationResult",
    "ExecutionResult",
    "PolicyActivationResult",
    "RefundAssessment",
    "RefundProposalResult",
    "SimulatorInjectionResult",
    "VerificationResult",
]
