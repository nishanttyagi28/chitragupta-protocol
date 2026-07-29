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


class DenyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str


class ExecuteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str
    policy_bundle_id: str | None = None


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
    "ApproveIn",
    "AssessIn",
    "DenyIn",
    "ExecuteIn",
    "ManifestSummary",
    "PolicyBundleCreateIn",
    "PrepareRequestIn",
    "PrincipalIn",
]
