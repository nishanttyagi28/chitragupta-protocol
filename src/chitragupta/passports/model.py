"""The Action Passport: a complete, honest record of one effect's lifecycle.

Deliberately excludes chain-of-thought or any free-form model reasoning --
only structured facts about what was proposed, approved, executed, and
observed (see docs/action-passports.md).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from chitragupta.domain.common import Principal
from chitragupta.domain.enums import ReversibilityClassification, RiskClassification
from chitragupta.domain.manifest import ParameterValue
from chitragupta.protocol.versioning import CURRENT_SCHEMA_VERSION


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
    was_revoked: bool = False

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

    # Lifecycle + cryptographic verification status
    lifecycle_state: str
    verification: PassportVerificationStatus


__all__ = ["ActionPassport", "PassportVerificationStatus"]
