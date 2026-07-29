"""Versioned quorum rules for multi-party authorization.

Like ``IntelligencePolicy`` (Phase 1), this is a plain, unsigned rule
set on its own; ``build_approval_policy_bundle`` wraps it in the same
signed ``PolicyBundle`` envelope introduced in Phase 2
(``policy_type="approval.v1"``), so quorum rules are pinned by hash the
same way scoring policies are.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import PolicyBundleIssuerNotAuthorizedError
from karmasakshi.policy.bundle import PolicyBundle

POLICY_TYPE_APPROVAL = "approval.v1"


@dataclass(frozen=True)
class ApprovalPolicy:
    """Quorum rules: how many distinct approvals are required, which
    roles must be represented, and who may never count toward quorum."""

    policy_id: str = "default"
    policy_version: str = "1.0"

    required_approvals: int = 1
    required_roles: tuple[str, ...] = ()
    forbid_proposer_as_approver: bool = True
    forbid_subject_as_approver: bool = True
    veto_on_any_dissent: bool = True
    cooling_off_seconds: int = 0
    #: Resource-protection bound: reject the whole evaluation (fail
    #: closed) rather than silently truncating if more statements than
    #: this are submitted at once.
    max_statements_considered: int = 100

    def __post_init__(self) -> None:
        if not self.policy_id or len(self.policy_id) > 128:
            raise ValueError("policy_id must be 1-128 chars")
        if "." not in self.policy_version:
            raise ValueError("policy_version must be a MAJOR.MINOR string")
        if self.required_approvals < 1:
            raise ValueError("required_approvals must be >= 1")
        if self.cooling_off_seconds < 0:
            raise ValueError("cooling_off_seconds must be >= 0")
        if self.max_statements_considered < self.required_approvals:
            raise ValueError("max_statements_considered must be >= required_approvals")
        for role in self.required_roles:
            if not role or len(role) > 64:
                raise ValueError(f"required_roles entry {role!r} must be 1-64 chars")
        if len(set(self.required_roles)) != len(self.required_roles):
            raise ValueError("required_roles must not contain duplicates")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "required_approvals": self.required_approvals,
            "required_roles": sorted(self.required_roles),
            "forbid_proposer_as_approver": self.forbid_proposer_as_approver,
            "forbid_subject_as_approver": self.forbid_subject_as_approver,
            "veto_on_any_dissent": self.veto_on_any_dissent,
            "cooling_off_seconds": self.cooling_off_seconds,
            "max_statements_considered": self.max_statements_considered,
        }

    def policy_hash(self) -> str:
        return canonical_hash(self.canonical_dict())


DEFAULT_APPROVAL_POLICY = ApprovalPolicy()


def build_approval_policy_bundle(
    policy: ApprovalPolicy,
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
    an agent principal (invariant #30 applied identically to approval
    policy bundles as to intelligence policy bundles)."""
    if issuer.principal_type == PrincipalType.AGENT:
        raise PolicyBundleIssuerNotAuthorizedError(
            "an agent principal cannot be the issuer of an approval policy bundle; "
            "the issuer must be a human or service principal (invariant #30)"
        )
    return PolicyBundle(
        bundle_id=bundle_id,
        bundle_version=bundle_version,
        policy_type=POLICY_TYPE_APPROVAL,
        payload=policy.canonical_dict(),
        issuer=issuer,
        tenant_id=tenant_id,
        created_at=created_at,
        effective_from=effective_from,
        effective_until=effective_until,
    )


def _as_int(payload: dict[str, object], key: str) -> int:
    if key not in payload:
        raise ValueError(f"approval policy payload is missing required key {key!r}")
    v = payload[key]
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"approval policy payload key {key!r} must be an int")
    return v


def _as_bool(payload: dict[str, object], key: str) -> bool:
    if key not in payload:
        raise ValueError(f"approval policy payload is missing required key {key!r}")
    v = payload[key]
    if not isinstance(v, bool):
        raise ValueError(f"approval policy payload key {key!r} must be a bool")
    return v


def _as_str(payload: dict[str, object], key: str) -> str:
    if key not in payload:
        raise ValueError(f"approval policy payload is missing required key {key!r}")
    v = payload[key]
    if not isinstance(v, str):
        raise ValueError(f"approval policy payload key {key!r} must be a string")
    return v


def _as_tuple_str(payload: dict[str, object], key: str) -> tuple[str, ...]:
    if key not in payload:
        raise ValueError(f"approval policy payload is missing required key {key!r}")
    v = payload[key]
    if not isinstance(v, list) or not all(isinstance(item, str) for item in v):
        raise ValueError(f"approval policy payload key {key!r} must be a list of strings")
    return tuple(v)


def approval_policy_from_bundle_payload(payload: dict[str, object]) -> ApprovalPolicy:
    """Reconstruct an :class:`ApprovalPolicy` from a verified bundle's
    payload. Only call this *after* ``policy.sealing.verify_policy_bundle``
    has succeeded. Raises ``ValueError`` on a malformed payload."""
    return ApprovalPolicy(
        policy_id=_as_str(payload, "policy_id"),
        policy_version=_as_str(payload, "policy_version"),
        required_approvals=_as_int(payload, "required_approvals"),
        required_roles=_as_tuple_str(payload, "required_roles"),
        forbid_proposer_as_approver=_as_bool(payload, "forbid_proposer_as_approver"),
        forbid_subject_as_approver=_as_bool(payload, "forbid_subject_as_approver"),
        veto_on_any_dissent=_as_bool(payload, "veto_on_any_dissent"),
        cooling_off_seconds=_as_int(payload, "cooling_off_seconds"),
        max_statements_considered=_as_int(payload, "max_statements_considered"),
    )


__all__ = [
    "DEFAULT_APPROVAL_POLICY",
    "POLICY_TYPE_APPROVAL",
    "ApprovalPolicy",
    "approval_policy_from_bundle_payload",
    "build_approval_policy_bundle",
]
