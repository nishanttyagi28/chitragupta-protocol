from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from karmasakshi.domain.common import AdapterIdentity, MonetaryAmount, Principal
from karmasakshi.domain.enums import (
    BlastRadiusClassification,
    PrincipalType,
    ReversibilityClassification,
    RiskClassification,
)
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.intelligence import AssessmentFacts, EffectIntelligenceEngine, IntelligencePolicy

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_ACTOR = Principal(principal_id="agent-1", principal_type=PrincipalType.AGENT)
_PRINCIPAL = Principal(principal_id="user-1", principal_type=PrincipalType.HUMAN)
_ADAPTER = AdapterIdentity(adapter_id="payment.simulator", adapter_version="1.0.0")

_risk = st.sampled_from(list(RiskClassification))
_reversibility = st.sampled_from(list(ReversibilityClassification))
_blast_radius = st.sampled_from(list(BlastRadiusClassification))
_amount = st.integers(min_value=0, max_value=10**9)
_ttl = st.integers(min_value=1, max_value=10**6)


@st.composite
def _manifests(draw: st.DrawFn) -> EffectManifest:
    risk = draw(_risk)
    reversibility = draw(_reversibility)
    blast_radius = draw(_blast_radius)
    amount = draw(_amount)
    ttl = draw(_ttl)
    has_cost = draw(st.booleans())
    return EffectManifest(
        manifest_id="11111111-1111-4111-8111-111111111111",
        effect_type="payment.transfer",
        actor=_ACTOR,
        principal=_PRINCIPAL,
        adapter=_ADAPTER,
        target_resource="payment:beneficiary/X",
        parameters={"amount": amount},
        risk=risk,
        reversibility=reversibility,
        blast_radius=blast_radius,
        estimated_cost=MonetaryAmount(currency="INR", minor_units=amount) if has_cost else None,
        idempotency_key="idem-1",
        created_at=_NOW,
        expires_at=_NOW + timedelta(seconds=ttl),
        nonce="nonce-1",
    )


@st.composite
def _facts(draw: st.DrawFn) -> AssessmentFacts:
    recurrence = draw(st.integers(min_value=0, max_value=1000))
    failures = draw(st.integers(min_value=0, max_value=recurrence))
    return AssessmentFacts(
        delegation_depth=draw(st.integers(min_value=0, max_value=20)),
        historical_recurrence_count=recurrence,
        historical_failure_count=failures,
        provider_idempotent=draw(st.one_of(st.none(), st.booleans())),
        compensation_feasible=draw(st.one_of(st.none(), st.booleans())),
        cross_tenant=draw(st.booleans()),
        unusual_parameter_change=draw(st.booleans()),
    )


_engine = EffectIntelligenceEngine()


@given(_manifests(), _facts())
@settings(max_examples=200, deadline=None)
def test_score_always_bounded(manifest: EffectManifest, facts: AssessmentFacts) -> None:
    assessment = _engine.assess(manifest, facts)
    assert 0 <= assessment.score <= 100


@given(_manifests(), _facts())
@settings(max_examples=200, deadline=None)
def test_assessment_hash_deterministic_across_repeated_calls(
    manifest: EffectManifest, facts: AssessmentFacts
) -> None:
    a1 = _engine.assess(manifest, facts)
    a2 = _engine.assess(manifest, facts)
    assert a1.deterministic_hash() == a2.deterministic_hash()
    assert a1.score == a2.score
    assert a1.risk_level == a2.risk_level
    assert a1.recommendation == a2.recommendation
    assert a1.signals == a2.signals


@given(_manifests(), _facts())
@settings(max_examples=200, deadline=None)
def test_deterministic_hash_matches_across_two_independent_engine_instances(
    manifest: EffectManifest, facts: AssessmentFacts
) -> None:
    policy = IntelligencePolicy()
    engine_a = EffectIntelligenceEngine(policy=policy)
    engine_b = EffectIntelligenceEngine(policy=IntelligencePolicy())
    a1 = engine_a.assess(manifest, facts)
    a2 = engine_b.assess(manifest, facts)
    assert a1.deterministic_hash() == a2.deterministic_hash()


@given(_manifests(), _facts())
@settings(max_examples=200, deadline=None)
def test_recommendation_consistent_with_score_thresholds(
    manifest: EffectManifest, facts: AssessmentFacts
) -> None:
    assessment = _engine.assess(manifest, facts)
    policy = _engine.policy
    # score >= block_threshold always forces BLOCK (independent of any
    # additional forced-block reason).
    if assessment.score >= policy.block_threshold:
        assert assessment.recommendation.value == "block"
    # ALLOW only ever happens below the review threshold.
    if assessment.recommendation.value == "allow":
        assert assessment.score < policy.review_threshold
    # REVIEW only ever happens at/above review threshold and below block
    # threshold (a forced block below block_threshold would be BLOCK, not
    # REVIEW, so REVIEW implies the score alone determined the outcome).
    if assessment.recommendation.value == "review":
        assert policy.review_threshold <= assessment.score < policy.block_threshold


@given(_manifests(), _facts())
@settings(max_examples=200, deadline=None)
def test_required_human_approvals_never_exceeds_policy_ceiling(
    manifest: EffectManifest, facts: AssessmentFacts
) -> None:
    assessment = _engine.assess(manifest, facts)
    assert assessment.required_human_approvals <= _engine.policy.max_required_human_approvals


@given(_manifests())
@settings(max_examples=100, deadline=None)
def test_higher_amount_never_scores_lower_than_zero_amount_same_currency(
    manifest: EffectManifest,
) -> None:
    if manifest.estimated_cost is None:
        return
    cheap = manifest.model_copy(
        update={"estimated_cost": MonetaryAmount(currency="INR", minor_units=0)}
    )
    expensive = manifest.model_copy(
        update={"estimated_cost": MonetaryAmount(currency="INR", minor_units=10**9)}
    )
    cheap_score = _engine.assess(cheap).score
    expensive_score = _engine.assess(expensive).score
    assert expensive_score >= cheap_score
