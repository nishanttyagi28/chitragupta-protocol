"""Versioned separation-of-duty rules (extreme-v2 Phase 4).

Like ``ApprovalPolicy`` (Phase 3) and ``IntelligencePolicy`` (Phase 1),
this is a plain, unsigned rule set on its own; ``build_separation_of_duty_policy_bundle``
wraps it in the same signed ``PolicyBundle`` envelope introduced in Phase 2
(``policy_type="separation.v1"``), so which role pairs are forbidden is
pinned by hash the same way scoring and quorum policies are.

Phase 3's ``forbid_proposer_as_approver``/``forbid_subject_as_approver``
are exactly two hard-coded instances of the general rule this module
generalizes: "principal P may not simultaneously hold role A and role B
for the same manifest." Phase 3's own logic is untouched by this module
-- a caller who wants both Phase 3's quorum-specific self-approval
checks *and* Phase 4's general separation matrix runs both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.duty.roles import ProtocolRole
from karmasakshi.errors import PolicyBundleIssuerNotAuthorizedError
from karmasakshi.policy.bundle import PolicyBundle

POLICY_TYPE_SEPARATION = "separation.v1"

#: Resource-protection bound on the forbidden-pair matrix, consistent
#: with the other small, fixed-size policy bounds in this codebase.
MAX_FORBIDDEN_ROLE_PAIRS = 64

#: A conservative, commonly-desired default: the principal who sealed a
#: manifest, or who proposed it, or who will execute it, must not also be
#: the one who approved it.
_DEFAULT_FORBIDDEN_PAIRS: tuple[tuple[str, str], ...] = (
    (ProtocolRole.SEALER.value, ProtocolRole.APPROVER.value),
    (ProtocolRole.PROPOSER.value, ProtocolRole.APPROVER.value),
    (ProtocolRole.APPROVER.value, ProtocolRole.EXECUTOR.value),
)


def _canonical_pair(pair: tuple[str, str]) -> tuple[str, str]:
    a, b = pair
    return (a, b) if a <= b else (b, a)


@dataclass(frozen=True)
class SeparationOfDutyPolicy:
    """Which role pairs may never be held by the same principal, for one
    manifest, under this policy."""

    policy_id: str = "default"
    policy_version: str = "1.0"
    forbidden_role_pairs: tuple[tuple[str, str], ...] = field(
        default_factory=lambda: _DEFAULT_FORBIDDEN_PAIRS
    )

    def __post_init__(self) -> None:
        if not self.policy_id or len(self.policy_id) > 128:
            raise ValueError("policy_id must be 1-128 chars")
        if "." not in self.policy_version:
            raise ValueError("policy_version must be a MAJOR.MINOR string")
        if len(self.forbidden_role_pairs) > MAX_FORBIDDEN_ROLE_PAIRS:
            raise ValueError(
                f"forbidden_role_pairs has {len(self.forbidden_role_pairs)} entries, "
                f"exceeding the {MAX_FORBIDDEN_ROLE_PAIRS} bound"
            )
        valid_roles = {r.value for r in ProtocolRole}
        canonicalized: set[tuple[str, str]] = set()
        for pair in self.forbidden_role_pairs:
            if len(pair) != 2:
                raise ValueError(f"forbidden role pair must have exactly 2 roles, got {pair!r}")
            role_a, role_b = pair
            if role_a not in valid_roles or role_b not in valid_roles:
                raise ValueError(f"forbidden role pair {pair!r} references an unknown role")
            if role_a == role_b:
                raise ValueError(
                    f"forbidden role pair {pair!r} pairs a role with itself, which is meaningless "
                    "(a single principal always holds its own role)"
                )
            canonical = _canonical_pair(pair)
            if canonical in canonicalized:
                raise ValueError(f"duplicate forbidden role pair (order-independent): {pair!r}")
            canonicalized.add(canonical)

    def canonical_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "forbidden_role_pairs": sorted(
                [list(_canonical_pair(pair)) for pair in self.forbidden_role_pairs]
            ),
        }

    def policy_hash(self) -> str:
        return canonical_hash(self.canonical_dict())


DEFAULT_SEPARATION_OF_DUTY_POLICY = SeparationOfDutyPolicy()


def build_separation_of_duty_policy_bundle(
    policy: SeparationOfDutyPolicy,
    *,
    bundle_id: str,
    bundle_version: str,
    issuer: Principal,
    created_at: datetime,
    effective_from: datetime,
    effective_until: datetime | None = None,
    tenant_id: str | None = None,
) -> PolicyBundle:
    """Wrap ``policy`` in an unsigned :class:`PolicyBundle`.

    Raises :class:`PolicyBundleIssuerNotAuthorizedError` if ``issuer`` is
    an agent principal (invariant #30 applied identically to separation
    policy bundles as to intelligence and approval policy bundles)."""
    if issuer.principal_type == PrincipalType.AGENT:
        raise PolicyBundleIssuerNotAuthorizedError(
            "an agent principal cannot be the issuer of a separation-of-duty policy bundle; "
            "the issuer must be a human or service principal (invariant #30)"
        )
    return PolicyBundle(
        bundle_id=bundle_id,
        bundle_version=bundle_version,
        policy_type=POLICY_TYPE_SEPARATION,
        payload=policy.canonical_dict(),
        issuer=issuer,
        tenant_id=tenant_id,
        created_at=created_at,
        effective_from=effective_from,
        effective_until=effective_until,
    )


def _as_str(payload: dict[str, object], key: str) -> str:
    if key not in payload:
        raise ValueError(f"separation policy payload is missing required key {key!r}")
    v = payload[key]
    if not isinstance(v, str):
        raise ValueError(f"separation policy payload key {key!r} must be a string")
    return v


def _as_role_pairs(payload: dict[str, object], key: str) -> tuple[tuple[str, str], ...]:
    if key not in payload:
        raise ValueError(f"separation policy payload is missing required key {key!r}")
    v = payload[key]
    if not isinstance(v, list):
        raise ValueError(f"separation policy payload key {key!r} must be a list")
    pairs: list[tuple[str, str]] = []
    for entry in v:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or not all(isinstance(x, str) for x in entry)
        ):
            raise ValueError(
                f"separation policy payload key {key!r} entries must each be a 2-element "
                f"list of strings, got {entry!r}"
            )
        pairs.append((entry[0], entry[1]))
    return tuple(pairs)


def separation_of_duty_policy_from_bundle_payload(
    payload: dict[str, object],
) -> SeparationOfDutyPolicy:
    """Reconstruct a :class:`SeparationOfDutyPolicy` from a verified
    bundle's payload. Only call this *after*
    ``policy.sealing.verify_policy_bundle`` has succeeded. Raises
    ``ValueError`` on a malformed payload."""
    return SeparationOfDutyPolicy(
        policy_id=_as_str(payload, "policy_id"),
        policy_version=_as_str(payload, "policy_version"),
        forbidden_role_pairs=_as_role_pairs(payload, "forbidden_role_pairs"),
    )


__all__ = [
    "DEFAULT_SEPARATION_OF_DUTY_POLICY",
    "MAX_FORBIDDEN_ROLE_PAIRS",
    "POLICY_TYPE_SEPARATION",
    "SeparationOfDutyPolicy",
    "build_separation_of_duty_policy_bundle",
    "separation_of_duty_policy_from_bundle_payload",
]
