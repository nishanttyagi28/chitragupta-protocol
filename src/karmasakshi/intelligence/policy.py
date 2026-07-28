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

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.domain.enums import (
    BlastRadiusClassification,
    ReversibilityClassification,
    RiskClassification,
)

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

__all__ = ["DEFAULT_INTELLIGENCE_POLICY", "IntelligencePolicy"]
