"""Deterministic evaluation of a :class:`RoleAssignment` against a
:class:`SeparationOfDutyPolicy` (extreme-v2 Phase 4).

Pure function, no I/O, no clock, no randomness -- the same inputs always
produce the same :class:`SeparationOfDutyResult`, mirroring
``approval.quorum.evaluate_quorum``'s determinism guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass

from karmasakshi.duty.policy import SeparationOfDutyPolicy
from karmasakshi.duty.roles import ProtocolRole, RoleAssignment


@dataclass(frozen=True)
class SeparationOfDutyViolation:
    role_a: str
    role_b: str
    principal_id: str


@dataclass(frozen=True)
class SeparationOfDutyResult:
    satisfied: bool
    violations: tuple[SeparationOfDutyViolation, ...]
    reason: str


def check_separation_of_duty(
    assignment: RoleAssignment, policy: SeparationOfDutyPolicy
) -> SeparationOfDutyResult:
    """Check whether any principal in ``assignment`` holds both roles of
    any pair in ``policy.forbidden_role_pairs``.

    A principal appears as a violation once per offending pair, even if
    it holds many roles -- each forbidden pair is an independent rule.
    """
    violations: list[SeparationOfDutyViolation] = []
    for role_a_value, role_b_value in policy.forbidden_role_pairs:
        principals_a = set(assignment.principals_for(ProtocolRole(role_a_value)))
        principals_b = set(assignment.principals_for(ProtocolRole(role_b_value)))
        for principal_id in sorted(principals_a & principals_b):
            violations.append(
                SeparationOfDutyViolation(
                    role_a=role_a_value, role_b=role_b_value, principal_id=principal_id
                )
            )
    if not violations:
        return SeparationOfDutyResult(
            satisfied=True, violations=(), reason="no separation-of-duty violations"
        )
    detail = "; ".join(
        f"{v.principal_id!r} holds both {v.role_a!r} and {v.role_b!r}" for v in violations
    )
    return SeparationOfDutyResult(
        satisfied=False,
        violations=tuple(violations),
        reason=f"{len(violations)} separation-of-duty violation(s): {detail}",
    )


__all__ = ["SeparationOfDutyResult", "SeparationOfDutyViolation", "check_separation_of_duty"]
