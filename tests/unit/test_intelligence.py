from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.audit.journal import AuditJournal
from karmasakshi.domain.common import MonetaryAmount, StateFingerprint
from karmasakshi.domain.enums import (
    BlastRadiusClassification,
    ReversibilityClassification,
    RiskClassification,
    StateFingerprintKind,
)
from karmasakshi.intelligence import (
    AssessmentFacts,
    EffectIntelligenceEngine,
    IntelligencePolicy,
    Recommendation,
    RiskLevel,
    VerificationStrength,
    derive_facts_from_audit,
)

# --- IntelligencePolicy ------------------------------------------------------


def test_default_policy_constructs_and_hashes() -> None:
    policy = IntelligencePolicy()
    assert policy.policy_hash().startswith("sha256:")


def test_policy_hash_independent_of_dict_construction_order() -> None:
    p1 = IntelligencePolicy(risk_base_points={"low": 5, "medium": 20, "high": 45, "critical": 70})
    p2 = IntelligencePolicy(risk_base_points={"critical": 70, "low": 5, "high": 45, "medium": 20})
    assert p1.policy_hash() == p2.policy_hash()


def test_policy_hash_changes_when_a_threshold_changes() -> None:
    p1 = IntelligencePolicy()
    p2 = IntelligencePolicy(block_threshold=90)
    assert p1.policy_hash() != p2.policy_hash()


def test_policy_hash_independent_of_restricted_effect_types_order() -> None:
    p1 = IntelligencePolicy(restricted_effect_types=("a.b", "c.d"))
    p2 = IntelligencePolicy(restricted_effect_types=("c.d", "a.b"))
    assert p1.policy_hash() == p2.policy_hash()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"policy_id": ""},
        {"policy_version": "1"},
        {"block_threshold": 101},
        {"block_threshold": -1},
        {"review_threshold": 90, "block_threshold": 80},
        {"risk_level_thresholds": (50, 25, 75)},
        {"risk_level_thresholds": (0, 50, 75)},
        {"max_acceptable_failure_rate": 1.5},
        {"max_delegation_depth": -1},
        {"max_recommended_ttl_seconds": 0},
        {"amount_thresholds": {"INR": (100, 50, 10)}},
    ],
)
def test_invalid_policy_construction_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        IntelligencePolicy(**kwargs)  # type: ignore[arg-type]


# --- AssessmentFacts ----------------------------------------------------------


def test_facts_default_is_all_unknown_or_zero() -> None:
    facts = AssessmentFacts()
    assert facts.delegation_depth == 0
    assert facts.historical_recurrence_count == 0
    assert facts.provider_idempotent is None
    assert facts.compensation_feasible is None
    assert facts.cross_tenant is False
    assert facts.policy_violations == ()


def test_facts_failure_count_cannot_exceed_recurrence_count() -> None:
    with pytest.raises(ValueError):
        AssessmentFacts(historical_recurrence_count=1, historical_failure_count=2)


def test_facts_negative_counts_rejected() -> None:
    with pytest.raises(ValueError):
        AssessmentFacts(delegation_depth=-1)
    with pytest.raises(ValueError):
        AssessmentFacts(historical_recurrence_count=-1)


# --- EffectIntelligenceEngine: basic scoring ----------------------------------


def test_low_risk_manifest_is_allowed_with_no_approvals(manifest_factory) -> None:
    manifest = manifest_factory(
        risk=RiskClassification.LOW,
        reversibility=ReversibilityClassification.REVERSIBLE,
        blast_radius=BlastRadiusClassification.SINGLE_RESOURCE,
    )
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest, AssessmentFacts(historical_recurrence_count=5))
    assert assessment.recommendation == Recommendation.ALLOW
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.required_human_approvals == 0
    assert assessment.required_service_approvals == 0
    assert assessment.cooling_off_period_seconds == 0


def test_critical_manifest_with_aggravating_facts_is_blocked(manifest_factory) -> None:
    manifest = manifest_factory(
        risk=RiskClassification.CRITICAL,
        reversibility=ReversibilityClassification.IRREVERSIBLE,
        blast_radius=BlastRadiusClassification.UNBOUNDED,
        amount_minor_units=50_000_000,
    )
    engine = EffectIntelligenceEngine()
    facts = AssessmentFacts(
        cross_tenant=True,
        unusual_parameter_change=True,
        provider_idempotent=False,
        compensation_feasible=False,
    )
    assessment = engine.assess(manifest, facts)
    assert assessment.score == 100
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.recommendation == Recommendation.BLOCK
    assert assessment.required_verification_strength == VerificationStrength.INDEPENDENT


def test_score_is_always_bounded_0_to_100(manifest_factory) -> None:
    manifest = manifest_factory(
        risk=RiskClassification.CRITICAL,
        reversibility=ReversibilityClassification.IRREVERSIBLE,
        blast_radius=BlastRadiusClassification.UNBOUNDED,
        amount_minor_units=999_999_999,
    )
    engine = EffectIntelligenceEngine()
    facts = AssessmentFacts(
        delegation_depth=8,
        cross_tenant=True,
        unusual_parameter_change=True,
        provider_idempotent=False,
        compensation_feasible=False,
        historical_recurrence_count=10,
        historical_failure_count=9,
        policy_violations=("manual review flagged this",),
    )
    assessment = engine.assess(manifest, facts)
    assert 0 <= assessment.score <= 100


def test_restricted_effect_type_forces_block_regardless_of_score(manifest_factory) -> None:
    manifest = manifest_factory(
        effect_type="allowed.type",
        risk=RiskClassification.LOW,
        reversibility=ReversibilityClassification.REVERSIBLE,
    )
    policy = IntelligencePolicy(restricted_effect_types=("payment.transfer",))
    manifest_restricted = manifest_factory(
        effect_type="payment.transfer",
        risk=RiskClassification.LOW,
        reversibility=ReversibilityClassification.REVERSIBLE,
    )
    engine = EffectIntelligenceEngine(policy=policy)
    allowed = engine.assess(manifest)
    assert allowed.recommendation != Recommendation.BLOCK

    blocked = engine.assess(manifest_restricted)
    assert blocked.recommendation == Recommendation.BLOCK
    assert any(s.name == "effect_type_restricted_by_policy" for s in blocked.signals)


def test_delegation_depth_exceeding_ceiling_forces_block(manifest_factory) -> None:
    manifest = manifest_factory(risk=RiskClassification.LOW)
    policy = IntelligencePolicy(max_delegation_depth=2)
    engine = EffectIntelligenceEngine(policy=policy)
    assessment = engine.assess(manifest, AssessmentFacts(delegation_depth=3))
    assert assessment.recommendation == Recommendation.BLOCK
    assert any(s.name == "delegation_depth_exceeds_policy_ceiling" for s in assessment.signals)


def test_delegation_depth_at_ceiling_is_scored_not_blocked(manifest_factory) -> None:
    manifest = manifest_factory(risk=RiskClassification.LOW)
    policy = IntelligencePolicy(max_delegation_depth=2)
    engine = EffectIntelligenceEngine(policy=policy)
    assessment = engine.assess(manifest, AssessmentFacts(delegation_depth=2))
    assert any(s.name == "delegation_depth_at_ceiling" for s in assessment.signals)


def test_compensation_infeasible_contradicts_compensatable_reversibility(manifest_factory) -> None:
    manifest = manifest_factory(
        risk=RiskClassification.MEDIUM, reversibility=ReversibilityClassification.COMPENSATABLE
    )
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest, AssessmentFacts(compensation_feasible=False))
    assert assessment.recommendation == Recommendation.BLOCK
    assert any(
        s.name == "compensation_feasibility_contradicts_manifest_reversibility"
        for s in assessment.signals
    )


def test_irreversible_and_confirmed_not_compensatable_adds_approval(manifest_factory) -> None:
    manifest = manifest_factory(
        risk=RiskClassification.MEDIUM, reversibility=ReversibilityClassification.IRREVERSIBLE
    )
    engine = EffectIntelligenceEngine()
    baseline = engine.assess(manifest, AssessmentFacts())
    aggravated = engine.assess(manifest, AssessmentFacts(compensation_feasible=False))
    assert aggravated.required_human_approvals > baseline.required_human_approvals
    assert any(s.name == "irreversible_and_not_compensatable" for s in aggravated.signals)


def test_cross_tenant_flag_adds_signal_and_extra_approval(manifest_factory) -> None:
    manifest = manifest_factory(risk=RiskClassification.MEDIUM)
    engine = EffectIntelligenceEngine()
    baseline = engine.assess(manifest, AssessmentFacts())
    cross_tenant = engine.assess(manifest, AssessmentFacts(cross_tenant=True))
    assert any(s.name == "cross_tenant_effect" for s in cross_tenant.signals)
    # +20 score points can only keep the same or raise the risk-level bucket
    # (never lowers it), and the signal itself adds +1 approval directly --
    # so approvals strictly increase, though not necessarily by exactly 1 if
    # the extra score also crosses a risk-level threshold.
    assert cross_tenant.required_human_approvals > baseline.required_human_approvals


def test_novel_effect_pattern_flagged_when_no_history(manifest_factory) -> None:
    manifest = manifest_factory(risk=RiskClassification.LOW)
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest, AssessmentFacts(historical_recurrence_count=0))
    assert any(s.name == "novel_effect_pattern_no_history" for s in assessment.signals)


def test_elevated_failure_rate_flagged(manifest_factory) -> None:
    manifest = manifest_factory(risk=RiskClassification.LOW)
    engine = EffectIntelligenceEngine()
    facts = AssessmentFacts(historical_recurrence_count=10, historical_failure_count=5)
    assessment = engine.assess(manifest, facts)
    assert any(s.name == "elevated_historical_failure_rate" for s in assessment.signals)


def test_sensitive_target_pattern_matched(manifest_factory) -> None:
    manifest = manifest_factory(target_resource="payment:beneficiary/admin-account")
    policy = IntelligencePolicy(sensitive_target_patterns=(r"admin",))
    engine = EffectIntelligenceEngine(policy=policy)
    assessment = engine.assess(manifest)
    assert any(s.name == "sensitive_target_pattern_matched" for s in assessment.signals)


def test_malformed_sensitive_pattern_fails_closed_not_silently_ignored(manifest_factory) -> None:
    manifest = manifest_factory()
    policy = IntelligencePolicy(sensitive_target_patterns=(r"[unclosed",))
    engine = EffectIntelligenceEngine(policy=policy)
    assessment = engine.assess(manifest)
    assert assessment.recommendation == Recommendation.BLOCK
    assert any(s.name == "sensitive_target_pattern_malformed" for s in assessment.signals)


def test_external_policy_violations_force_block(manifest_factory) -> None:
    manifest = manifest_factory(risk=RiskClassification.LOW)
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest, AssessmentFacts(policy_violations=("kyc_check_failed",)))
    assert assessment.recommendation == Recommendation.BLOCK
    assert any(s.name == "external_policy_violation:kyc_check_failed" for s in assessment.signals)


def test_monetary_exposure_tiers(manifest_factory) -> None:
    policy = IntelligencePolicy(amount_thresholds={"INR": (100, 1000, 10000)})
    engine = EffectIntelligenceEngine(policy=policy)

    low = manifest_factory(amount_minor_units=50, currency="INR")
    mid = manifest_factory(amount_minor_units=500, currency="INR")
    high = manifest_factory(amount_minor_units=5000, currency="INR")
    extreme = manifest_factory(amount_minor_units=50000, currency="INR")

    scores = [engine.assess(m).score for m in (low, mid, high, extreme)]
    assert scores == sorted(scores)
    assert scores[0] < scores[-1]


def test_unclassified_currency_flagged(manifest_factory) -> None:
    policy = IntelligencePolicy(amount_thresholds={"INR": (100, 1000, 10000)})
    engine = EffectIntelligenceEngine(policy=policy)
    manifest = manifest_factory(amount_minor_units=500, currency="USD")
    assessment = engine.assess(manifest)
    assert any(
        s.name == "unclassified_currency_uses_default_thresholds" for s in assessment.signals
    )


def test_high_risk_without_cost_estimate_flagged(
    manifest_factory, now, agent_principal, human_principal, adapter_identity
) -> None:
    from karmasakshi.domain.manifest import EffectManifest

    manifest = EffectManifest(
        manifest_id="22222222-2222-4222-8222-222222222222",
        effect_type="email.send",
        actor=agent_principal,
        principal=human_principal,
        adapter=adapter_identity,
        target_resource="email:inbox/x",
        parameters={},
        risk=RiskClassification.HIGH,
        reversibility=ReversibilityClassification.IRREVERSIBLE,
        blast_radius=BlastRadiusClassification.SINGLE_RESOURCE,
        estimated_cost=None,
        idempotency_key="idem-no-cost",
        created_at=now,
        expires_at=now + timedelta(seconds=300),
        nonce="nonce-no-cost",
    )
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest)
    assert any(s.name == "high_risk_without_cost_estimate" for s in assessment.signals)


def test_no_state_fingerprint_for_non_reversible_effect_flagged(manifest_factory) -> None:
    manifest = manifest_factory(
        reversibility=ReversibilityClassification.IRREVERSIBLE, state_fingerprint=None
    )
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest)
    assert any(
        s.name == "no_state_fingerprint_for_non_reversible_effect" for s in assessment.signals
    )


def test_state_fingerprint_present_suppresses_that_signal(manifest_factory) -> None:
    fp = StateFingerprint(kind=StateFingerprintKind.ROW_VERSION, value="v1")
    manifest = manifest_factory(
        reversibility=ReversibilityClassification.IRREVERSIBLE, state_fingerprint=fp
    )
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest)
    assert not any(
        s.name == "no_state_fingerprint_for_non_reversible_effect" for s in assessment.signals
    )


def test_long_lived_manifest_flagged(manifest_factory) -> None:
    policy = IntelligencePolicy(max_recommended_ttl_seconds=60)
    engine = EffectIntelligenceEngine(policy=policy)
    manifest = manifest_factory(ttl_seconds=3600)
    assessment = engine.assess(manifest)
    assert any(s.name == "manifest_lifetime_exceeds_recommended_window" for s in assessment.signals)


def test_provider_idempotency_unknown_flagged_by_default(manifest_factory) -> None:
    manifest = manifest_factory()
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest)
    assert any(s.name == "provider_idempotency_unknown" for s in assessment.signals)


def test_provider_known_idempotent_suppresses_unknown_signal(manifest_factory) -> None:
    manifest = manifest_factory()
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest, AssessmentFacts(provider_idempotent=True))
    assert not any(s.name == "provider_idempotency_unknown" for s in assessment.signals)


# --- determinism ---------------------------------------------------------------


def test_identical_inputs_produce_identical_deterministic_hash(manifest_factory) -> None:
    manifest = manifest_factory()
    facts = AssessmentFacts(cross_tenant=True, historical_recurrence_count=3)
    policy = IntelligencePolicy()
    engine_a = EffectIntelligenceEngine(policy=policy)
    engine_b = EffectIntelligenceEngine(policy=IntelligencePolicy())  # separate instance

    a1 = engine_a.assess(manifest, facts)
    a2 = engine_b.assess(manifest, facts)

    assert a1.deterministic_hash() == a2.deterministic_hash()
    # but per-call identity/timestamp fields are still distinct
    assert a1.assessment_id != a2.assessment_id


def test_different_manifest_hash_changes_deterministic_hash(manifest_factory) -> None:
    m1 = manifest_factory(manifest_id="11111111-1111-4111-8111-111111111111")
    m2 = manifest_factory(manifest_id="33333333-3333-4333-8333-333333333333")
    engine = EffectIntelligenceEngine()
    a1 = engine.assess(m1)
    a2 = engine.assess(m2)
    assert a1.deterministic_hash() != a2.deterministic_hash()


def test_different_policy_hash_changes_deterministic_hash(manifest_factory) -> None:
    manifest = manifest_factory()
    a1 = EffectIntelligenceEngine(policy=IntelligencePolicy()).assess(manifest)
    a2 = EffectIntelligenceEngine(policy=IntelligencePolicy(block_threshold=99)).assess(manifest)
    assert a1.deterministic_hash() != a2.deterministic_hash()


# --- derive_facts_from_audit ----------------------------------------------------


def test_derive_facts_from_audit_counts_prior_recurrence_and_failures(
    manifest_factory, fixed_clock
) -> None:
    journal = AuditJournal(clock=fixed_clock)
    manifest = manifest_factory(manifest_id="99999999-9999-4999-8999-999999999999")

    # Two prior manifests by the same actor+effect_type: one succeeded, one failed.
    journal.record(
        event_type="manifest.prepared",
        decision="allowed",
        manifest_id="prior-1",
        actor_id=manifest.actor.principal_id,
        metadata={"effect_type": manifest.effect_type},
    )
    journal.record(
        event_type="effect.committed",
        decision="allowed",
        manifest_id="prior-1",
        actor_id=manifest.actor.principal_id,
    )
    journal.record(
        event_type="manifest.prepared",
        decision="allowed",
        manifest_id="prior-2",
        actor_id=manifest.actor.principal_id,
        metadata={"effect_type": manifest.effect_type},
    )
    journal.record(
        event_type="effect.commit_failed",
        decision="blocked_x",
        manifest_id="prior-2",
        actor_id=manifest.actor.principal_id,
    )
    # A different effect_type by the same actor must not count.
    journal.record(
        event_type="manifest.prepared",
        decision="allowed",
        manifest_id="prior-other-type",
        actor_id=manifest.actor.principal_id,
        metadata={"effect_type": "some.other.type"},
    )

    facts = derive_facts_from_audit(journal, manifest)
    assert facts.historical_recurrence_count == 2
    assert facts.historical_failure_count == 1


def test_derive_facts_from_audit_empty_journal_yields_zero_recurrence(
    manifest_factory, fixed_clock
) -> None:
    journal = AuditJournal(clock=fixed_clock)
    manifest = manifest_factory()
    facts = derive_facts_from_audit(journal, manifest)
    assert facts.historical_recurrence_count == 0
    assert facts.historical_failure_count == 0


def test_derive_facts_passes_through_explicit_facts(manifest_factory, fixed_clock) -> None:
    journal = AuditJournal(clock=fixed_clock)
    manifest = manifest_factory()
    facts = derive_facts_from_audit(
        journal,
        manifest,
        delegation_depth=4,
        provider_idempotent=True,
        compensation_feasible=True,
        cross_tenant=True,
        unusual_parameter_change=True,
        extra_policy_violations=("x",),
    )
    assert facts.delegation_depth == 4
    assert facts.provider_idempotent is True
    assert facts.compensation_feasible is True
    assert facts.cross_tenant is True
    assert facts.unusual_parameter_change is True
    assert facts.policy_violations == ("x",)


# --- monetary edge cases: currency comparison guard ----------------------------


def test_monetary_amount_zero_units_is_valid(manifest_factory) -> None:
    manifest = manifest_factory(amount_minor_units=0)
    engine = EffectIntelligenceEngine()
    assessment = engine.assess(manifest)
    assert 0 <= assessment.score <= 100


def test_estimated_cost_amount_object_reused_directly() -> None:
    # Guards against accidental float leakage in canonicalization of the
    # monetary exposure signal detail string.
    amount = MonetaryAmount(currency="INR", minor_units=12345)
    assert str(amount) == "INR 12345"
