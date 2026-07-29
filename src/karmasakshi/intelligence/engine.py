"""The deterministic Effect Intelligence Engine.

Computes a structured, reproducible ``EffectAssessment`` from an
``EffectManifest`` plus a versioned ``IntelligencePolicy`` and explicit
``AssessmentFacts``. It is a pure function of those three inputs: no
randomness, no network calls, no LLM call. Every signal is a named,
structured rule over manifest fields, policy thresholds, and supplied
facts (docs/effect-intelligence.md). Operating rule #8 applies here in
its strongest form -- there is no model in this loop at all, only
versioned arithmetic, so "the LLM must not make the final decision" is
true by construction rather than by discipline.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.domain.enums import ReversibilityClassification, RiskClassification
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.intelligence.facts import AssessmentFacts
from karmasakshi.intelligence.model import (
    EffectAssessment,
    Recommendation,
    RiskLevel,
    RiskSignal,
    VerificationStrength,
)
from karmasakshi.intelligence.policy import IntelligencePolicy

_BASE_HUMAN_APPROVALS: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

_WITNESS_QUORUM: dict[RiskLevel, int] = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

_VERIFICATION_STRENGTH: dict[RiskLevel, VerificationStrength] = {
    RiskLevel.LOW: VerificationStrength.STANDARD,
    RiskLevel.MEDIUM: VerificationStrength.STANDARD,
    RiskLevel.HIGH: VerificationStrength.STRONG,
    RiskLevel.CRITICAL: VerificationStrength.INDEPENDENT,
}


@dataclass
class _ScoreBuilder:
    signals: list[RiskSignal] = field(default_factory=list)
    score: int = 0
    forced_block_reasons: list[str] = field(default_factory=list)

    def add(self, name: str, weight: int, detail: str) -> None:
        self.signals.append(RiskSignal(name=name, weight=weight, detail=detail))
        self.score += weight

    def force_block(self, name: str, detail: str) -> None:
        self.signals.append(RiskSignal(name=name, weight=0, detail=detail))
        self.forced_block_reasons.append(name)

    @property
    def signal_names(self) -> set[str]:
        return {s.name for s in self.signals}


class EffectIntelligenceEngine:
    """Stateless scorer bound to one ``IntelligencePolicy``. Construct one
    per policy version in use; reuse it across ``assess`` calls."""

    def __init__(
        self, policy: IntelligencePolicy | None = None, clock: Clock = SYSTEM_CLOCK
    ) -> None:
        self._policy = policy or IntelligencePolicy()
        self._clock = clock

    @property
    def policy(self) -> IntelligencePolicy:
        return self._policy

    def assess(
        self, manifest: EffectManifest, facts: AssessmentFacts | None = None
    ) -> EffectAssessment:
        facts = facts if facts is not None else AssessmentFacts()
        policy = self._policy
        b = _ScoreBuilder()

        self._score_declared_classification(manifest, policy, b)
        self._score_monetary_exposure(manifest, policy, b)
        self._score_state_and_preconditions(manifest, b)
        self._score_manifest_lifetime(manifest, policy, b)
        self._score_target_sensitivity(manifest, policy, b)
        self._score_restricted_effect_type(manifest, policy, b)
        self._score_delegation_depth(policy, facts, b)
        self._score_historical_recurrence(policy, facts, b)
        self._score_provider_capabilities(manifest, facts, b)
        self._score_cross_tenant(facts, b)
        self._score_unusual_parameter_change(facts, b)
        self._score_external_policy_violations(facts, b)

        score = min(b.score, 100)
        risk_level = self._risk_level(score, policy)
        recommendation = self._recommendation(score, bool(b.forced_block_reasons), policy)
        required_human_approvals, required_service_approvals = self._required_approvals(
            risk_level, b.signal_names, policy
        )
        cooling_off = self._cooling_off_seconds(risk_level, policy)
        witness_quorum = _WITNESS_QUORUM[risk_level]
        verification_strength = self._verification_strength(manifest, facts, risk_level)
        explanation = self._explanation(score, risk_level, recommendation, b)

        return EffectAssessment(
            assessment_id=str(uuid.uuid4()),
            manifest_id=manifest.manifest_id,
            manifest_hash=manifest.canonical_hash(),
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_hash=policy.policy_hash(),
            score=score,
            risk_level=risk_level,
            signals=tuple(b.signals),
            recommendation=recommendation,
            required_human_approvals=required_human_approvals,
            required_service_approvals=required_service_approvals,
            cooling_off_period_seconds=cooling_off,
            required_witness_quorum=witness_quorum,
            required_verification_strength=verification_strength,
            explanation=explanation,
            assessed_at=self._clock.now(),
        )

    # --- individual signal groups -----------------------------------------

    @staticmethod
    def _score_declared_classification(
        manifest: EffectManifest, policy: IntelligencePolicy, b: _ScoreBuilder
    ) -> None:
        b.add(
            "declared_risk_classification",
            policy.risk_base_points.get(manifest.risk.value, 0),
            f"manifest.risk={manifest.risk.value}",
        )
        b.add(
            "declared_blast_radius",
            policy.blast_radius_points.get(manifest.blast_radius.value, 0),
            f"manifest.blast_radius={manifest.blast_radius.value}",
        )
        b.add(
            "declared_reversibility",
            policy.reversibility_points.get(manifest.reversibility.value, 0),
            f"manifest.reversibility={manifest.reversibility.value}",
        )

    @staticmethod
    def _score_monetary_exposure(
        manifest: EffectManifest, policy: IntelligencePolicy, b: _ScoreBuilder
    ) -> None:
        cost = manifest.estimated_cost
        if cost is None:
            if manifest.risk in (RiskClassification.HIGH, RiskClassification.CRITICAL):
                b.add(
                    "high_risk_without_cost_estimate",
                    8,
                    "manifest declares high/critical risk but no estimated_cost",
                )
            return
        thresholds = policy.amount_thresholds.get(cost.currency, policy.default_amount_thresholds)
        low, mid, high = thresholds
        units = cost.minor_units
        if units < low:
            tier_points = 0
        elif units < mid:
            tier_points = 10
        elif units < high:
            tier_points = 20
        else:
            tier_points = 35
        b.add(
            "monetary_exposure_tier",
            tier_points,
            f"estimated_cost={cost} thresholds(low,mid,high)={thresholds}",
        )
        if cost.currency not in policy.amount_thresholds:
            b.add(
                "unclassified_currency_uses_default_thresholds",
                5,
                f"no policy thresholds configured for currency {cost.currency!r}",
            )

    @staticmethod
    def _score_state_and_preconditions(manifest: EffectManifest, b: _ScoreBuilder) -> None:
        if (
            manifest.state_fingerprint is None
            and manifest.reversibility != ReversibilityClassification.REVERSIBLE
        ):
            b.add(
                "no_state_fingerprint_for_non_reversible_effect",
                10,
                "manifest has no state_fingerprint and is not classified reversible",
            )
        if not manifest.preconditions and manifest.risk in (
            RiskClassification.HIGH,
            RiskClassification.CRITICAL,
        ):
            b.add(
                "no_preconditions_declared_for_high_risk_effect",
                10,
                f"manifest.risk={manifest.risk.value} but preconditions is empty",
            )

    @staticmethod
    def _score_manifest_lifetime(
        manifest: EffectManifest, policy: IntelligencePolicy, b: _ScoreBuilder
    ) -> None:
        ttl_seconds = int((manifest.expires_at - manifest.created_at).total_seconds())
        if ttl_seconds > policy.max_recommended_ttl_seconds:
            b.add(
                "manifest_lifetime_exceeds_recommended_window",
                8,
                f"ttl_seconds={ttl_seconds} > policy max {policy.max_recommended_ttl_seconds}",
            )

    @staticmethod
    def _score_target_sensitivity(
        manifest: EffectManifest, policy: IntelligencePolicy, b: _ScoreBuilder
    ) -> None:
        for pattern in policy.sensitive_target_patterns:
            try:
                matched = re.search(pattern, manifest.target_resource) is not None
            except re.error:
                # A malformed policy pattern must never silently pass; treat
                # it as a policy authoring defect that forces review, not as
                # "no match" (fail closed on an indeterminate policy state).
                b.force_block(
                    "sensitive_target_pattern_malformed",
                    f"policy pattern {pattern!r} is not a valid regex",
                )
                continue
            if matched:
                b.add(
                    "sensitive_target_pattern_matched",
                    15,
                    f"target_resource={manifest.target_resource!r} matched pattern {pattern!r}",
                )

    @staticmethod
    def _score_restricted_effect_type(
        manifest: EffectManifest, policy: IntelligencePolicy, b: _ScoreBuilder
    ) -> None:
        if manifest.effect_type in policy.restricted_effect_types:
            b.force_block(
                "effect_type_restricted_by_policy",
                f"effect_type {manifest.effect_type!r} is on policy {policy.policy_id!r}'s "
                "restricted list",
            )

    @staticmethod
    def _score_delegation_depth(
        policy: IntelligencePolicy, facts: AssessmentFacts, b: _ScoreBuilder
    ) -> None:
        if facts.delegation_depth > policy.max_delegation_depth:
            b.force_block(
                "delegation_depth_exceeds_policy_ceiling",
                f"depth={facts.delegation_depth} > ceiling={policy.max_delegation_depth}",
            )
        elif facts.delegation_depth == policy.max_delegation_depth:
            b.add(
                "delegation_depth_at_ceiling",
                20,
                f"depth={facts.delegation_depth} == ceiling={policy.max_delegation_depth}",
            )

    @staticmethod
    def _score_historical_recurrence(
        policy: IntelligencePolicy, facts: AssessmentFacts, b: _ScoreBuilder
    ) -> None:
        if facts.historical_recurrence_count == 0:
            b.add(
                "novel_effect_pattern_no_history",
                6,
                "no prior instances of this actor+effect_type found",
            )
            return
        failure_rate = facts.historical_failure_count / facts.historical_recurrence_count
        if failure_rate > policy.max_acceptable_failure_rate:
            b.add(
                "elevated_historical_failure_rate",
                25,
                f"failure_rate={failure_rate:.2f} "
                f"> policy max {policy.max_acceptable_failure_rate}",
            )

    @staticmethod
    def _score_provider_capabilities(
        manifest: EffectManifest, facts: AssessmentFacts, b: _ScoreBuilder
    ) -> None:
        if facts.provider_idempotent is None:
            b.add(
                "provider_idempotency_unknown",
                8,
                "adapter/provider idempotency capability was not declared",
            )
        elif facts.provider_idempotent is False and manifest.risk in (
            RiskClassification.HIGH,
            RiskClassification.CRITICAL,
        ):
            b.add(
                "non_idempotent_provider_high_risk",
                12,
                "provider does not guarantee idempotent execution for a high/critical-risk effect",
            )

        if facts.compensation_feasible is None:
            if manifest.reversibility != ReversibilityClassification.REVERSIBLE:
                b.add(
                    "compensation_feasibility_unknown",
                    8,
                    "compensation feasibility was not declared for a non-reversible effect",
                )
            return

        if facts.compensation_feasible is False:
            if manifest.reversibility == ReversibilityClassification.COMPENSATABLE:
                b.force_block(
                    "compensation_feasibility_contradicts_manifest_reversibility",
                    "manifest declares reversibility=compensatable but facts assert "
                    "compensation is not feasible",
                )
            elif (
                manifest.reversibility == ReversibilityClassification.IRREVERSIBLE
                and manifest.risk != RiskClassification.LOW
            ):
                b.add(
                    "irreversible_and_not_compensatable",
                    15,
                    "effect is irreversible and compensation is confirmed infeasible",
                )

    @staticmethod
    def _score_cross_tenant(facts: AssessmentFacts, b: _ScoreBuilder) -> None:
        if facts.cross_tenant:
            b.add(
                "cross_tenant_effect",
                20,
                "effect crosses tenant boundaries (advisory only: multi-tenant enforcement "
                "is not implemented in this protocol version)",
            )

    @staticmethod
    def _score_unusual_parameter_change(facts: AssessmentFacts, b: _ScoreBuilder) -> None:
        if facts.unusual_parameter_change:
            b.add(
                "unusual_parameter_change_detected",
                12,
                "caller flagged this manifest's parameters as an unusual change vs. history",
            )

    @staticmethod
    def _score_external_policy_violations(facts: AssessmentFacts, b: _ScoreBuilder) -> None:
        for violation in facts.policy_violations:
            b.force_block(f"external_policy_violation:{violation}", violation)

    # --- aggregation ---------------------------------------------------------

    @staticmethod
    def _risk_level(score: int, policy: IntelligencePolicy) -> RiskLevel:
        lo, mid, hi = policy.risk_level_thresholds
        if score < lo:
            return RiskLevel.LOW
        if score < mid:
            return RiskLevel.MEDIUM
        if score < hi:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    @staticmethod
    def _recommendation(
        score: int, forced_block: bool, policy: IntelligencePolicy
    ) -> Recommendation:
        if forced_block or score >= policy.block_threshold:
            return Recommendation.BLOCK
        if score >= policy.review_threshold:
            return Recommendation.REVIEW
        return Recommendation.ALLOW

    @staticmethod
    def _required_approvals(
        risk_level: RiskLevel, signal_names: set[str], policy: IntelligencePolicy
    ) -> tuple[int, int]:
        approvals = _BASE_HUMAN_APPROVALS[risk_level]
        if "cross_tenant_effect" in signal_names:
            approvals += 1
        if "irreversible_and_not_compensatable" in signal_names:
            approvals += 1
        approvals = min(approvals, policy.max_required_human_approvals)
        service_approvals = 1 if "non_idempotent_provider_high_risk" in signal_names else 0
        return approvals, service_approvals

    @staticmethod
    def _cooling_off_seconds(risk_level: RiskLevel, policy: IntelligencePolicy) -> int:
        return {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.HIGH: policy.cooling_off_high_seconds,
            RiskLevel.CRITICAL: policy.cooling_off_critical_seconds,
        }[risk_level]

    @staticmethod
    def _verification_strength(
        manifest: EffectManifest, facts: AssessmentFacts, risk_level: RiskLevel
    ) -> VerificationStrength:
        strength = _VERIFICATION_STRENGTH[risk_level]
        if (
            facts.provider_idempotent is False
            and manifest.reversibility == ReversibilityClassification.IRREVERSIBLE
        ):
            strength = VerificationStrength.INDEPENDENT
        return strength

    @staticmethod
    def _explanation(
        score: int, risk_level: RiskLevel, recommendation: Recommendation, b: _ScoreBuilder
    ) -> str:
        parts = [
            f"score={score}/100 risk_level={risk_level.value} "
            f"recommendation={recommendation.value}."
        ]
        contributing = [s for s in b.signals if s.weight > 0]
        if contributing:
            rendered = "; ".join(f"{s.name}(+{s.weight})" for s in contributing)
            parts.append(f"Contributing signals: {rendered}.")
        if b.forced_block_reasons:
            parts.append("Forced BLOCK: " + "; ".join(b.forced_block_reasons) + ".")
        return " ".join(parts)


__all__ = ["EffectIntelligenceEngine"]
