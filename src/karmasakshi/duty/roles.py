"""Explicit protocol roles and per-manifest role assignments
(extreme-v2 Phase 4: Separation of Duties).

Phase 3 already has *ad hoc* versions of these roles scattered through
``authorize_with_quorum()``'s parameters (``proposer``, ``subject``
(executor), the approving principals). This module formalizes them into
a reusable, structural record -- a :class:`RoleAssignment` -- so that
"which principal held which role for this manifest" is a first-class,
inspectable fact rather than something implicit in argument names.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from karmasakshi.errors import RoleAssignmentError

#: Resource-protection bound: reject an oversized role assignment outright
#: (fail closed) rather than silently truncating it, consistent with the
#: bounds already enforced on approval statement batches (Phase 3) and
#: policy payload sizes (Phase 2).
MAX_ROLE_ASSIGNMENTS = 256


class ProtocolRole(str, Enum):
    """The explicit set of roles a principal may hold with respect to one
    manifest's lifecycle. Named after the lifecycle stages in
    docs/architecture.md (PROPOSE -> PREPARE -> ASSESS -> SEAL ->
    AUTHORIZE -> COMMIT -> VERIFY) plus the cross-cutting COMPENSATOR and
    AUDITOR roles."""

    PROPOSER = "proposer"
    RESOLVER = "resolver"
    ASSESSOR = "assessor"
    SEALER = "sealer"
    APPROVER = "approver"
    EXECUTOR = "executor"
    VERIFIER = "verifier"
    WITNESS = "witness"
    COMPENSATOR = "compensator"
    AUDITOR = "auditor"


@dataclass(frozen=True)
class RoleAssignment:
    """Which principal(s) held which :class:`ProtocolRole`(s) for one exact
    manifest, identified by its canonical hash (the same anchor
    ``ApprovalStatement`` and ``ExecutionGrant`` bind to).

    A role may be held by more than one principal (e.g. multiple
    approvers under quorum); a principal may hold more than one role.
    Whether that is *permitted* is exactly what
    :func:`karmasakshi.duty.enforcement.check_separation_of_duty` decides
    -- this structure only records the facts, it does not judge them.
    """

    manifest_hash: str
    assignments: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if (
            not self.manifest_hash.startswith("sha256:")
            or len(self.manifest_hash) != len("sha256:") + 64
        ):
            raise RoleAssignmentError(
                f"role assignment manifest_hash must be a sha256:<hex> digest, "
                f"got {self.manifest_hash!r}"
            )
        if len(self.assignments) > MAX_ROLE_ASSIGNMENTS:
            raise RoleAssignmentError(
                f"role assignment has {len(self.assignments)} entries, "
                f"exceeding the {MAX_ROLE_ASSIGNMENTS} bound"
            )
        seen: set[tuple[str, str]] = set()
        valid_roles = {r.value for r in ProtocolRole}
        for role, principal_id in self.assignments:
            if role not in valid_roles:
                raise RoleAssignmentError(f"unknown protocol role {role!r}")
            if not principal_id or len(principal_id) > 256:
                raise RoleAssignmentError(
                    f"role assignment principal_id must be 1-256 chars, got {principal_id!r}"
                )
            pair = (role, principal_id)
            if pair in seen:
                raise RoleAssignmentError(
                    f"duplicate role assignment entry: role={role!r} principal_id={principal_id!r}"
                )
            seen.add(pair)

    def principals_for(self, role: ProtocolRole) -> tuple[str, ...]:
        """All distinct principal_ids holding ``role``, sorted for
        determinism."""
        return tuple(sorted({pid for r, pid in self.assignments if r == role.value}))

    def merge(self, other: RoleAssignment | None) -> RoleAssignment:
        """Combine this assignment with ``other``, deduplicating entries.

        Raises :class:`RoleAssignmentError` if ``other`` is bound to a
        different manifest hash -- silently merging role facts across two
        different manifests would be a correctness bug, never a
        convenience worth having.
        """
        if other is None:
            return self
        if other.manifest_hash != self.manifest_hash:
            raise RoleAssignmentError(
                f"cannot merge role assignments for different manifests: "
                f"{self.manifest_hash!r} != {other.manifest_hash!r}"
            )
        combined = tuple(sorted(set(self.assignments) | set(other.assignments)))
        return RoleAssignment(manifest_hash=self.manifest_hash, assignments=combined)

    def as_role_participation(self) -> dict[str, str]:
        """A flat ``{role: comma_joined_sorted_principal_ids}`` view,
        suitable for audit metadata (``dict[str, str]``) and the Action
        Passport's ``role_participation`` field."""
        by_role: dict[str, set[str]] = {}
        for role, principal_id in self.assignments:
            by_role.setdefault(role, set()).add(principal_id)
        return {role: ",".join(sorted(pids)) for role, pids in sorted(by_role.items())}

    @classmethod
    def empty(cls, manifest_hash: str) -> RoleAssignment:
        return cls(manifest_hash=manifest_hash, assignments=())

    @classmethod
    def of(cls, manifest_hash: str, role: ProtocolRole, *principal_ids: str) -> RoleAssignment:
        """Build a single-role assignment, e.g.
        ``RoleAssignment.of(h, ProtocolRole.SEALER, "user:alice")``.
        Duplicate ``principal_ids`` are deduplicated rather than rejected
        -- passing the same principal twice is redundant, not an error."""
        return cls(
            manifest_hash=manifest_hash,
            assignments=tuple(sorted({(role.value, pid) for pid in principal_ids})),
        )


def base_role_assignment(
    manifest_hash: str,
    *,
    proposer_id: str,
    executor_id: str,
    approver_ids: tuple[str, ...],
) -> RoleAssignment:
    """The role facts derivable directly from an ``authorize()`` /
    ``authorize_with_quorum()`` call's own parameters, before any
    caller-supplied additional roles (e.g. sealer, witness, verifier) are
    merged in via :meth:`RoleAssignment.merge`.

    Pure and deterministic so a caller building an Action Passport later
    can reconstruct the identical base assignment from the same
    proposer/subject/approver principal ids it already used at
    authorization time, without the engine needing to persist or return
    the assignment itself.
    """
    assignments = {
        (ProtocolRole.PROPOSER.value, proposer_id),
        (ProtocolRole.EXECUTOR.value, executor_id),
    }
    for approver_id in approver_ids:
        assignments.add((ProtocolRole.APPROVER.value, approver_id))
    return RoleAssignment(manifest_hash=manifest_hash, assignments=tuple(sorted(assignments)))


__all__ = [
    "MAX_ROLE_ASSIGNMENTS",
    "ProtocolRole",
    "RoleAssignment",
    "base_role_assignment",
]
