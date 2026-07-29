"""API request/response schemas -- kept separate from the domain models so
the wire contract can evolve independently of internal representations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from karmasakshi.domain.enums import PrincipalType


class PrincipalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    principal_type: PrincipalType
    display_name: str | None = None


class PrepareRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter: Literal["sqlite", "email", "payment"]
    actor: PrincipalIn
    principal: PrincipalIn
    idempotency_key: str = ""
    ttl_seconds: int = 300
    fields: dict[str, str | int | bool | None] = {}


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: PrincipalIn
    subject: PrincipalIn
    audience: list[str] | None = None
    max_uses: int = 1
    ttl_seconds: int = 300
    policy_bundle_id: str | None = None
    separation_policy_bundle_id: str | None = None
    roles: list[str] = []
    decision_envelope_id: str | None = None
    causal_graph_id: str | None = None


class DenyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str


class ExecuteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str
    policy_bundle_id: str | None = None
    decision_envelope_id: str | None = None
    causal_graph_id: str | None = None


class ParameterConstraintIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["exact", "enum", "integer_range", "monetary_range"]
    exact_value: str | int | bool | None = None
    allowed_values: list[str | int | bool | None] | None = None
    min_int: int | None = None
    max_int: int | None = None
    currency: str | None = None
    min_minor_units: int | None = None
    max_minor_units: int | None = None


class DecisionEnvelopeCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    envelope_id: str
    effect_type: str
    adapter_id: str
    adapter_version: str = "1.0"
    target_resources: list[str]
    constraints: dict[str, ParameterConstraintIn]
    issuer: PrincipalIn
    ttl_seconds: int = 3600
    max_cost_currency: str | None = None
    max_cost_minor_units: int | None = None
    causal_graph_id: str | None = None
    forbid_unknown_parameters: bool = True
    require_all_constrained_parameters: bool = True


class DecisionEnvelopeSubstituteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    choices: dict[str, str | int | bool | None] = {}


class PolicyBundleCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    bundle_version: str = "1.0"
    issuer: PrincipalIn
    tenant_id: str | None = None
    effective_seconds: int = 30 * 24 * 3600
    block_threshold: int = 85
    review_threshold: int = 40
    max_delegation_depth: int = 8
    restricted_effect_types: list[str] = []
    sensitive_target_patterns: list[str] = []


class ApprovalPolicyBundleCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    bundle_version: str = "1.0"
    issuer: PrincipalIn
    tenant_id: str | None = None
    effective_seconds: int = 30 * 24 * 3600
    required_approvals: int = 1
    required_roles: list[str] = []
    forbid_proposer_as_approver: bool = True
    forbid_subject_as_approver: bool = True
    veto_on_any_dissent: bool = True
    cooling_off_seconds: int = 0


class SeparationOfDutyPolicyBundleCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    bundle_version: str = "1.0"
    issuer: PrincipalIn
    tenant_id: str | None = None
    effective_seconds: int = 30 * 24 * 3600
    #: Each entry "role_a:role_b"; empty uses the built-in default matrix.
    forbidden_role_pairs: list[str] = []


class ApprovalStatementIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_policy_bundle_id: str
    approver: PrincipalIn
    decision: Literal["approve", "dissent"] = "approve"
    role: str | None = None
    reason: str | None = None
    ttl_seconds: int = 3600


class QuorumEvaluateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_policy_bundle_id: str
    proposer: PrincipalIn
    subject: PrincipalIn


class QuorumGrantIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_policy_bundle_id: str
    grant_issuer: PrincipalIn
    proposer: PrincipalIn
    subject: PrincipalIn
    audience: list[str] | None = None
    max_uses: int = 1
    ttl_seconds: int = 300
    policy_bundle_id: str | None = None
    separation_policy_bundle_id: str | None = None
    roles: list[str] = []


class AssessIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delegation_depth: int = 0
    historical_recurrence_count: int = 0
    historical_failure_count: int = 0
    provider_idempotent: bool | None = None
    compensation_feasible: bool | None = None
    cross_tenant: bool = False
    unusual_parameter_change: bool = False
    policy_violations: list[str] = []
    from_audit_history: bool = False


class CausalEdgeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parent_manifest_id: str
    child_manifest_id: str
    relation: Literal["causes", "depends_on", "compensates", "verifies"] = "causes"


class CausalGraphCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_ids: list[str]
    edges: list[CausalEdgeIn]


class ManifestSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_id: str
    manifest_hash: str
    effect_type: str
    target_resource: str
    lifecycle_state: str
    risk: str
    reversibility: str
    created_at: datetime


__all__ = [
    "ApprovalPolicyBundleCreateIn",
    "ApprovalStatementIn",
    "ApproveIn",
    "AssessIn",
    "CausalEdgeIn",
    "CausalGraphCreateIn",
    "DecisionEnvelopeCreateIn",
    "DecisionEnvelopeSubstituteIn",
    "DenyIn",
    "ExecuteIn",
    "ManifestSummary",
    "ParameterConstraintIn",
    "PolicyBundleCreateIn",
    "PrepareRequestIn",
    "PrincipalIn",
    "QuorumEvaluateIn",
    "QuorumGrantIn",
    "SeparationOfDutyPolicyBundleCreateIn",
]
