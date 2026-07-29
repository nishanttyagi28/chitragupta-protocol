"""Separation of duties: explicit protocol roles, a signed
role-pair-forbidding policy, and deterministic enforcement
(extreme-v2 Phase 4). See docs/separation-of-duties.md."""

from __future__ import annotations

from karmasakshi.duty.enforcement import (
    SeparationOfDutyResult,
    SeparationOfDutyViolation,
    check_separation_of_duty,
)
from karmasakshi.duty.policy import (
    DEFAULT_SEPARATION_OF_DUTY_POLICY,
    MAX_FORBIDDEN_ROLE_PAIRS,
    POLICY_TYPE_SEPARATION,
    SeparationOfDutyPolicy,
    build_separation_of_duty_policy_bundle,
    separation_of_duty_policy_from_bundle_payload,
)
from karmasakshi.duty.roles import (
    MAX_ROLE_ASSIGNMENTS,
    ProtocolRole,
    RoleAssignment,
    base_role_assignment,
)

__all__ = [
    "DEFAULT_SEPARATION_OF_DUTY_POLICY",
    "MAX_FORBIDDEN_ROLE_PAIRS",
    "MAX_ROLE_ASSIGNMENTS",
    "POLICY_TYPE_SEPARATION",
    "ProtocolRole",
    "RoleAssignment",
    "SeparationOfDutyPolicy",
    "SeparationOfDutyResult",
    "SeparationOfDutyViolation",
    "base_role_assignment",
    "build_separation_of_duty_policy_bundle",
    "check_separation_of_duty",
    "separation_of_duty_policy_from_bundle_payload",
]
