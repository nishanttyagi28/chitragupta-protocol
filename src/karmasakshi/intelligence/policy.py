"""Versioned, deterministic scoring policy for the Effect Intelligence Engine.

This is a *scoring* policy only (extreme-v2 Phase 1). It carries no
cryptographic signature and does not itself gate authorization -- a later
phase (signed policy bundles) wraps a policy like this in a signed,
versioned envelope and binds its hash into the authorization grant
itself. Until then, :class:`~karmasakshi.intelligence.model.EffectAssessment`
is advisory: it is computed deterministically and recorded in the audit
journal, but nothing in ``engine.authorize()``/``engine.commit()`` reads
or enforces its recommendation. See docs/effect-intelligence.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import (
    BlastRadiusClassification,
    PrincipalType,
    ReversibilityClassification,
    RiskClassification,
)
from karmasakshi.errors import PolicyBundleIssuerNotAuthorizedError
from karmasakshi.policy.bundle import PolicyBundle

DEFAULT_RISK_BASE_POINTS: dict[str, int] = {
    RiskClassification.LOW.value: 5,
    RiskClassification.MEDIUM.value: 20,
    RiskClassification.HIGH.value: 45,
    RiskClassification.CRITICAL.value: 70,
}

DEFAULT_BLAST_RADIUS_POINTS: dict[str, int] = {
    BlastRadiusClassification.SINGLE_RESOURCE.value: 0,
    BlastRadiusClassification.BOUNDED_SET.value: 5,
    BlastRadiusClassification.BROAD.value: 15,
    BlastRadiusClassification.UNBOUNDED.value: 25,
}

DEFAULT_REVERSIBILITY_POINTS: dict[str, int] = {
    ReversibilityClassification.REVERSIBLE.value: 0,
    ReversibilityClassification.COMPENSATABLE.value: 5,
    ReversibilityClassification.IRREVERSIBLE.value: 15,
}


@dataclass(frozen=True)
class IntelligencePolicy:
    """Every threshold the Effect Intelligence Engine uses to score a
    manifest. Two policies with the same field values always produce the
    same :meth:`policy_hash`, independent of dict/tuple ordering."""

    policy_id: str = "default"
    policy_version: str = "1.0"

    risk_base_points: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_RISK_BASE_POINTS))
    blast_radius_points: dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_BLAST_RADIUS_POINTS)
    )
    reversibility_points: dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_REVERSIBILITY_POINTS)
    )

    #: currency -> (low, mid, high) minor-unit thresholds; monetary exposure
    #: is scored 0/10/20/35 points for amounts below low/mid/high/above high.
    amount_thresholds: dict[str, tuple[int, int, int]] = field(default_factory=dict)
    default_amount_thresholds: tuple[int, int, int] = (10_000_00, 100_000_00, 1_000_000_00)

    max_recommended_ttl_seconds: int = 3600
    sensitive_target_patterns: tuple[str, ...] = ()
    restricted_effect_types: tuple[str, ...] = ()
    max_delegation_depth: int = 8
    max_acceptable_failure_rate: float = 0.2

    block_threshold: int = 85
    review_threshold: int = 40
    #: score < [0] -> LOW, < [1] -> MEDIUM, < [2] -> HIGH, else CRITICAL.
    risk_level_thresholds: tuple[int, int, int] = (25, 50, 75)

    max_required_human_approvals: int = 5
    cooling_off_high_seconds: int = 60
    cooling_off_critical_seconds: int = 300

    def __post_init__(self) -> None:
        if not self.policy_id or len(self.policy_id) > 128:
            raise ValueError("policy_id must be 1-128 chars")
        if "." not in self.policy_version:
            raise ValueError("policy_version must be a MAJOR.MINOR string")
        if not (0 <= self.block_threshold <= 100):
            raise ValueError("block_threshold must be 0-100")
        if not (0 <= self.review_threshold <= self.block_threshold):
            raise ValueError("review_threshold must be between 0 and block_threshold")
        lo, mid, hi = self.risk_level_thresholds
        if not (0 < lo < mid < hi <= 100):
            raise ValueError("risk_level_thresholds must be strictly increasing within (0, 100]")
        if not (0.0 <= self.max_acceptable_failure_rate <= 1.0):
            raise ValueError("max_acceptable_failure_rate must be between 0.0 and 1.0")
        if self.max_delegation_depth < 0:
            raise ValueError("max_delegation_depth must be >= 0")
        if self.max_recommended_ttl_seconds <= 0:
            raise ValueError("max_recommended_ttl_seconds must be > 0")
        for currency, thresholds in self.amount_thresholds.items():
            lo_a, mid_a, hi_a = thresholds
            if not (0 <= lo_a < mid_a < hi_a):
                raise ValueError(f"amount_thresholds[{currency!r}] must be strictly increasing")

    def canonical_dict(self) -> dict[str, object]:
        """A plain-primitive representation suitable for canonical hashing.
        Dict/tuple contents are sorted so that logically identical policies
        (same rules, different construction order) hash identically."""
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "risk_base_points": dict(sorted(self.risk_base_points.items())),
            "blast_radius_points": dict(sorted(self.blast_radius_points.items())),
            "reversibility_points": dict(sorted(self.reversibility_points.items())),
            "amount_thresholds": {
                currency: list(thresholds)
                for currency, thresholds in sorted(self.amount_thresholds.items())
            },
            "default_amount_thresholds": list(self.default_amount_thresholds),
            "max_recommended_ttl_seconds": self.max_recommended_ttl_seconds,
            "sensitive_target_patterns": sorted(self.sensitive_target_patterns),
            "restricted_effect_types": sorted(self.restricted_effect_types),
            "max_delegation_depth": self.max_delegation_depth,
            # floats are rejected by the canonical serializer (see
            # canonical/serialize.py); represent exactly via its repr string.
            "max_acceptable_failure_rate": repr(self.max_acceptable_failure_rate),
            "block_threshold": self.block_threshold,
            "review_threshold": self.review_threshold,
            "risk_level_thresholds": list(self.risk_level_thresholds),
            "max_required_human_approvals": self.max_required_human_approvals,
            "cooling_off_high_seconds": self.cooling_off_high_seconds,
            "cooling_off_critical_seconds": self.cooling_off_critical_seconds,
        }

    def policy_hash(self) -> str:
        return canonical_hash(self.canonical_dict())


DEFAULT_INTELLIGENCE_POLICY = IntelligencePolicy()

#: The ``policy_type`` a signed ``PolicyBundle`` must declare to be
#: interpreted as an ``IntelligencePolicy`` payload (see
#: ``build_policy_bundle``/``policy_from_bundle_payload`` below and
#: docs/policy-bundles.md).
POLICY_TYPE_INTELLIGENCE = "intelligence.v1"


def build_policy_bundle(
    policy: IntelligencePolicy,
    *,
    bundle_id: str,
    bundle_version: str,
    issuer: Principal,
    created_at: datetime,
    effective_from: datetime,
    effective_until: datetime | None = None,
    tenant_id: str | None = None,
) -> PolicyBundle:
    """Wrap ``policy`` in an unsigned :class:`PolicyBundle`, ready for
    ``policy.sealing.seal_policy_bundle``.

    Raises :class:`PolicyBundleIssuerNotAuthorizedError` if ``issuer`` is
    an agent principal (invariant #30 applied to policy bundles: an agent
    may draft policy content but may never be the authorizing issuer of
    the bundle that governs it)."""
    if issuer.principal_type == PrincipalType.AGENT:
        raise PolicyBundleIssuerNotAuthorizedError(
            "an agent principal cannot be the issuer of a policy bundle; the issuer "
            "must be a human or service principal (invariant #30)"
        )
    return PolicyBundle(
        bundle_id=bundle_id,
        bundle_version=bundle_version,
        policy_type=POLICY_TYPE_INTELLIGENCE,
        payload=policy.canonical_dict(),
        issuer=issuer,
        tenant_id=tenant_id,
        created_at=created_at,
        effective_from=effective_from,
        effective_until=effective_until,
    )


def _require(payload: dict[str, object], key: str) -> object:
    if key not in payload:
        raise ValueError(f"policy bundle payload is missing required key {key!r}")
    return payload[key]


def _as_str(payload: dict[str, object], key: str) -> str:
    v = _require(payload, key)
    if not isinstance(v, str):
        raise ValueError(
            f"policy bundle payload key {key!r} must be a string, got {type(v).__name__}"
        )
    return v


def _as_int(payload: dict[str, object], key: str) -> int:
    v = _require(payload, key)
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(
            f"policy bundle payload key {key!r} must be an int, got {type(v).__name__}"
        )
    return v


def _as_dict_str_int(payload: dict[str, object], key: str) -> dict[str, int]:
    v = _require(payload, key)
    if not isinstance(v, dict):
        raise ValueError(
            f"policy bundle payload key {key!r} must be an object, got {type(v).__name__}"
        )
    result: dict[str, int] = {}
    for k, val in v.items():
        if not isinstance(k, str) or not isinstance(val, int) or isinstance(val, bool):
            raise ValueError(f"policy bundle payload key {key!r} must map str -> int")
        result[k] = val
    return result


def _as_tuple_str(payload: dict[str, object], key: str) -> tuple[str, ...]:
    v = _require(payload, key)
    if not isinstance(v, list) or not all(isinstance(item, str) for item in v):
        raise ValueError(f"policy bundle payload key {key!r} must be a list of strings")
    return tuple(v)


def _as_int3(payload: dict[str, object], key: str) -> tuple[int, int, int]:
    v = _require(payload, key)
    if not isinstance(v, list) or len(v) != 3 or not all(isinstance(item, int) for item in v):
        raise ValueError(f"policy bundle payload key {key!r} must be a 3-element list of ints")
    a, b, c = v
    return (a, b, c)


def _as_amount_thresholds(payload: dict[str, object], key: str) -> dict[str, tuple[int, int, int]]:
    v = _require(payload, key)
    if not isinstance(v, dict):
        raise ValueError(f"policy bundle payload key {key!r} must be an object")
    result: dict[str, tuple[int, int, int]] = {}
    for currency, thresholds in v.items():
        if (
            not isinstance(currency, str)
            or not isinstance(thresholds, list)
            or len(thresholds) != 3
            or not all(isinstance(item, int) for item in thresholds)
        ):
            raise ValueError(f"policy bundle payload key {key!r} is malformed")
        a, b, c = thresholds
        result[currency] = (a, b, c)
    return result


def policy_from_bundle_payload(payload: dict[str, object]) -> IntelligencePolicy:
    """Reconstruct an :class:`IntelligencePolicy` from a verified bundle's
    payload. Only call this *after*
    ``policy.sealing.verify_policy_bundle`` has succeeded -- this function
    does no cryptographic verification of its own, it only parses already-
    trusted content back into a policy object. Raises ``ValueError`` if the
    payload's shape does not match what ``IntelligencePolicy.canonical_dict()``
    produces (fail closed on a malformed payload rather than crash
    unpredictably or silently substitute a default)."""
    return IntelligencePolicy(
        policy_id=_as_str(payload, "policy_id"),
        policy_version=_as_str(payload, "policy_version"),
        risk_base_points=_as_dict_str_int(payload, "risk_base_points"),
        blast_radius_points=_as_dict_str_int(payload, "blast_radius_points"),
        reversibility_points=_as_dict_str_int(payload, "reversibility_points"),
        amount_thresholds=_as_amount_thresholds(payload, "amount_thresholds"),
        default_amount_thresholds=_as_int3(payload, "default_amount_thresholds"),
        max_recommended_ttl_seconds=_as_int(payload, "max_recommended_ttl_seconds"),
        sensitive_target_patterns=_as_tuple_str(payload, "sensitive_target_patterns"),
        restricted_effect_types=_as_tuple_str(payload, "restricted_effect_types"),
        max_delegation_depth=_as_int(payload, "max_delegation_depth"),
        # canonical_dict() stores this as repr(float) to keep floats out of
        # the canonicalized payload (canonical/serialize.py rejects floats);
        # repr()/float() round-trip exactly for any float Python can produce.
        max_acceptable_failure_rate=float(_as_str(payload, "max_acceptable_failure_rate")),
        block_threshold=_as_int(payload, "block_threshold"),
        review_threshold=_as_int(payload, "review_threshold"),
        risk_level_thresholds=_as_int3(payload, "risk_level_thresholds"),
        max_required_human_approvals=_as_int(payload, "max_required_human_approvals"),
        cooling_off_high_seconds=_as_int(payload, "cooling_off_high_seconds"),
        cooling_off_critical_seconds=_as_int(payload, "cooling_off_critical_seconds"),
    )


__all__ = [
    "DEFAULT_INTELLIGENCE_POLICY",
    "POLICY_TYPE_INTELLIGENCE",
    "IntelligencePolicy",
    "build_policy_bundle",
    "policy_from_bundle_payload",
]
