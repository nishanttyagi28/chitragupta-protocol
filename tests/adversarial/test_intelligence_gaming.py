"""Adversarial tests for the Effect Intelligence Engine: attempts to game
the deterministic score into a favorable recommendation, or to exploit
policy-authoring edge cases into an unsafe default.

None of these are cryptographic attacks (the assessment is advisory, not
yet a signed/bound authorization gate -- see docs/effect-intelligence.md)
but they pin down the scoring engine's own fail-closed behavior, which
later phases (signed policy bundles, M-of-N authorization) will build on.
"""

from __future__ import annotations

from karmasakshi.domain.enums import ReversibilityClassification, RiskClassification
from karmasakshi.intelligence import (
    AssessmentFacts,
    EffectIntelligenceEngine,
    IntelligencePolicy,
    Recommendation,
)


def test_favorable_history_cannot_offset_a_restricted_effect_type(manifest_factory) -> None:
    """An attacker floods the audit history with clean prior manifests to
    look trustworthy, then submits a restricted effect type. The restricted
    list forces BLOCK unconditionally -- no amount of favorable history
    overrides it."""
    manifest = manifest_factory(
        effect_type="payment.wire_transfer_international",
        risk=RiskClassification.LOW,
        reversibility=ReversibilityClassification.REVERSIBLE,
    )
    policy = IntelligencePolicy(restricted_effect_types=("payment.wire_transfer_international",))
    engine = EffectIntelligenceEngine(policy=policy)
    facts = AssessmentFacts(
        historical_recurrence_count=10_000,
        historical_failure_count=0,
        provider_idempotent=True,
        compensation_feasible=True,
    )
    assessment = engine.assess(manifest, facts)
    assert assessment.recommendation == Recommendation.BLOCK


def test_favorable_history_cannot_offset_delegation_depth_ceiling_breach(manifest_factory) -> None:
    manifest = manifest_factory(risk=RiskClassification.LOW)
    policy = IntelligencePolicy(max_delegation_depth=3)
    engine = EffectIntelligenceEngine(policy=policy)
    facts = AssessmentFacts(
        delegation_depth=4,
        historical_recurrence_count=10_000,
        historical_failure_count=0,
        provider_idempotent=True,
        compensation_feasible=True,
    )
    assessment = engine.assess(manifest, facts)
    assert assessment.recommendation == Recommendation.BLOCK


def test_a_single_policy_violation_among_many_favorable_facts_still_blocks(
    manifest_factory,
) -> None:
    manifest = manifest_factory(risk=RiskClassification.LOW)
    engine = EffectIntelligenceEngine()
    facts = AssessmentFacts(
        historical_recurrence_count=1000,
        historical_failure_count=0,
        provider_idempotent=True,
        compensation_feasible=True,
        policy_violations=("sanctions_list_match",),
    )
    assessment = engine.assess(manifest, facts)
    assert assessment.recommendation == Recommendation.BLOCK
    assert assessment.score < engine.policy.block_threshold  # score alone would not have blocked


def test_declaring_compensatable_while_confirmed_infeasible_is_never_allow(
    manifest_factory,
) -> None:
    """A manifest that self-declares reversibility=compensatable while the
    facts (e.g. from an adapter capability check) confirm compensation is
    not actually feasible is an internal contradiction, not a low-risk
    situation -- it must never resolve to ALLOW."""
    manifest = manifest_factory(
        risk=RiskClassification.LOW, reversibility=ReversibilityClassification.COMPENSATABLE
    )
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest, AssessmentFacts(compensation_feasible=False))
    assert assessment.recommendation != Recommendation.ALLOW


def test_reversible_effect_is_not_penalized_for_unrelated_compensation_fact(
    manifest_factory,
) -> None:
    """reversibility=REVERSIBLE means the effect is undone by direct
    reversal, not by a separate compensation mechanism -- so
    compensation_feasible is not applicable and must not itself force a
    block for a REVERSIBLE effect. This pins the intentional scope of the
    consistency check above (COMPENSATABLE/IRREVERSIBLE only)."""
    manifest = manifest_factory(
        risk=RiskClassification.LOW, reversibility=ReversibilityClassification.REVERSIBLE
    )
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest, AssessmentFacts(compensation_feasible=False))
    assert not any(
        s.name == "compensation_feasibility_contradicts_manifest_reversibility"
        for s in assessment.signals
    )


def test_score_cannot_go_negative_no_matter_how_favorable_the_facts(manifest_factory) -> None:
    manifest = manifest_factory(
        risk=RiskClassification.LOW,
        reversibility=ReversibilityClassification.REVERSIBLE,
        amount_minor_units=0,
    )
    engine = EffectIntelligenceEngine(
        policy=IntelligencePolicy(amount_thresholds={"INR": (1, 2, 3)})
    )
    facts = AssessmentFacts(
        historical_recurrence_count=999,
        historical_failure_count=0,
        provider_idempotent=True,
        compensation_feasible=True,
    )
    assessment = engine.assess(manifest, facts)
    assert assessment.score >= 0


def test_block_threshold_boundary_is_exact(manifest_factory) -> None:
    manifest = manifest_factory(risk=RiskClassification.LOW)
    policy = IntelligencePolicy(block_threshold=50, review_threshold=10)
    engine = EffectIntelligenceEngine(policy=policy)
    # score just under the boundary must not block via score alone.
    just_under = engine.assess(manifest, AssessmentFacts(delegation_depth=0))
    if just_under.score < 50:
        assert just_under.recommendation != Recommendation.BLOCK


def test_duplicate_policy_violation_strings_still_force_exactly_one_block(
    manifest_factory,
) -> None:
    manifest = manifest_factory(risk=RiskClassification.LOW)
    engine = EffectIntelligenceEngine()
    facts = AssessmentFacts(policy_violations=("dup", "dup", "dup"))
    assessment = engine.assess(manifest, facts)
    assert assessment.recommendation == Recommendation.BLOCK


def test_malformed_policy_pattern_never_silently_downgrades_to_allow(manifest_factory) -> None:
    """A policy author's typo (an unclosed regex character class) must fail
    closed -- if it silently matched nothing, a manifest that should have
    hit a sensitive-target rule could sail through as ALLOW."""
    manifest = manifest_factory(risk=RiskClassification.LOW, target_resource="admin-payout-account")
    policy = IntelligencePolicy(sensitive_target_patterns=(r"admin(",))
    engine = EffectIntelligenceEngine(policy=policy)
    assessment = engine.assess(manifest)
    assert assessment.recommendation == Recommendation.BLOCK


def test_two_engines_disagreeing_on_policy_cannot_be_reconciled_by_hash_alone(
    manifest_factory,
) -> None:
    """Different policies must produce different policy_hash values, so a
    downstream consumer binding to a specific policy_hash (a future phase)
    cannot be fooled by a looser policy that happens to allow the same
    manifest."""
    manifest = manifest_factory(risk=RiskClassification.MEDIUM)
    reference_score = EffectIntelligenceEngine().assess(manifest).score

    strict = EffectIntelligenceEngine(
        policy=IntelligencePolicy(
            block_threshold=max(reference_score - 1, 1),
            review_threshold=max(reference_score - 2, 0),
        )
    )
    loose = EffectIntelligenceEngine(
        policy=IntelligencePolicy(block_threshold=100, review_threshold=99)
    )
    a_strict = strict.assess(manifest)
    a_loose = loose.assess(manifest)
    assert a_strict.policy_hash != a_loose.policy_hash
    assert a_strict.recommendation == Recommendation.BLOCK
    assert a_loose.recommendation != Recommendation.BLOCK
