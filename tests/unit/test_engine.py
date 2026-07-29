from __future__ import annotations

import threading
from datetime import timedelta

import pytest

from karmasakshi.crypto import generate_signing_key
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import (
    AdapterMismatchError,
    GrantAudienceError,
    GrantExhaustedError,
    GrantExpiredError,
    GrantManifestMismatchError,
    GrantRevokedError,
    InvalidSignatureError,
    ManifestTamperedError,
    StaleManifestError,
)
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.state_machine import LifecycleState


def _prepare_and_seal(engine, adapter, manifest, signing_key):
    prepared = engine.prepare(adapter, manifest, context=None)
    return engine.seal(prepared, signing_key)


def other_signing_key_factory(key_id):
    return generate_signing_key(f"key-{key_id}")


def _authorize(engine, sealed, *, issuer, subject, issuer_signing_key, now, **overrides):
    kwargs = {
        "issuer": issuer,
        "subject": subject,
        "audience": ("payment.simulator",),
        "allowed_effect_types": (sealed.manifest.effect_type,),
        "scope": ScopeConstraints(),
        "not_before": now,
        "expires_at": now + timedelta(minutes=5),
        "signing_key": issuer_signing_key,
    }
    kwargs.update(overrides)
    return engine.authorize(sealed, **kwargs)


@pytest.fixture
def authorized(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    """A ready-to-commit (engine, sealed, grant) tuple sharing one engine instance."""
    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )
    return engine, sealed, grant


def test_happy_path_prepare_seal_authorize_commit_verify(
    authorized, fake_adapter, fake_adapter_state
):
    engine, sealed, grant = authorized
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success
    assert fake_adapter_state.committed
    proof = engine.verify(sealed.manifest, result, fake_adapter, context=None)
    assert proof.matched_expected
    assert engine.get_lifecycle_state(sealed.manifest.manifest_id) == LifecycleState.VERIFIED


def test_grant_bound_to_different_manifest_is_rejected(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    keyring,
    now,
    fake_adapter,
):
    engine = engine_factory()
    manifest_a = manifest_factory(manifest_id="manifest-a", target_resource="payment:beneficiary/A")
    manifest_b = manifest_factory(manifest_id="manifest-b", target_resource="payment:beneficiary/B")
    sealed_a = _prepare_and_seal(engine, fake_adapter, manifest_a, issuer_signing_key)
    sealed_b = _prepare_and_seal(engine, fake_adapter, manifest_b, issuer_signing_key)
    grant_for_a = _authorize(
        engine,
        sealed_a,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )
    # Attacker tries to use the grant approved for manifest A to execute manifest B.
    with pytest.raises(GrantManifestMismatchError):
        engine.commit(sealed_b, grant_for_a, fake_adapter, context=None)


def test_changed_target_after_seal_invalidates_seal(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )
    tampered_manifest = manifest_factory(target_resource="payment:beneficiary/ATTACKER")
    tampered_sealed = sealed.model_copy(update={"manifest": tampered_manifest})
    with pytest.raises(ManifestTamperedError):
        engine.commit(tampered_sealed, grant, fake_adapter, context=None)


def test_forged_seal_signature_with_unchanged_content_is_blocked(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    other_signing_key,
    now,
    fake_adapter,
):
    # Regression test: the manifest content (and therefore its hash) is
    # completely unchanged -- only the seal's signature bytes are forged.
    # commit() must still fail closed via cryptographic verification, not
    # just hash-based tamper detection.
    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )
    forged_signature = other_signing_key.sign(sealed.seal.manifest_hash.encode("utf-8"))
    forged_seal = sealed.seal.model_copy(update={"signature": forged_signature})
    forged_sealed = sealed.model_copy(update={"seal": forged_seal})
    with pytest.raises(InvalidSignatureError):
        engine.commit(forged_sealed, grant, fake_adapter, context=None)


def test_expired_grant_is_blocked(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        not_before=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=1),
    )
    with pytest.raises(GrantExpiredError):
        engine.commit(sealed, grant, fake_adapter, context=None)


def test_revoked_grant_is_blocked(authorized, fake_adapter, human_principal):
    engine, sealed, grant = authorized
    revoked_transitioned = engine.revoke(
        grant, sealed.manifest.manifest_id, revoked_by=human_principal
    )
    assert revoked_transitioned is True
    with pytest.raises(GrantRevokedError):
        engine.commit(sealed, grant, fake_adapter, context=None)


def test_revocation_after_commit_does_not_undo_effect(
    authorized, fake_adapter, fake_adapter_state, human_principal
):
    engine, sealed, grant = authorized
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success
    revoked_transitioned = engine.revoke(
        grant, sealed.manifest.manifest_id, revoked_by=human_principal
    )
    assert revoked_transitioned is False  # past the safe checkpoint; committed effect stands
    assert engine.get_lifecycle_state(sealed.manifest.manifest_id) == LifecycleState.COMMITTED
    assert len(fake_adapter_state.committed) == 1


def test_adapter_identity_mismatch_is_blocked(authorized, fake_adapter, fake_adapter_state):
    engine, sealed, grant = authorized
    fake_adapter.adapter_version = "9.9.9"
    try:
        with pytest.raises(AdapterMismatchError):
            engine.commit(sealed, grant, fake_adapter, context=None)
    finally:
        fake_adapter.adapter_version = "1.0.0"


def test_effect_type_not_in_grant_is_blocked(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        allowed_effect_types=("payment.refund",),
    )
    with pytest.raises(GrantAudienceError):
        engine.commit(sealed, grant, fake_adapter, context=None)


def test_adapter_not_in_audience_is_blocked(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        audience=("some.other.adapter",),
    )
    with pytest.raises(GrantAudienceError):
        engine.commit(sealed, grant, fake_adapter, context=None)


def test_stale_manifest_detected_on_precondition_change(
    authorized, fake_adapter, fake_adapter_state
):
    engine, sealed, grant = authorized
    fake_adapter_state.precondition_ok = False
    with pytest.raises(StaleManifestError):
        engine.commit(sealed, grant, fake_adapter, context=None)
    assert engine.get_lifecycle_state(sealed.manifest.manifest_id) == LifecycleState.FAILED
    # the grant's use was released, not consumed, by the stale-state failure
    assert engine.context.grant_store.get_use_count(grant.grant_id) == 0


def test_single_use_grant_cannot_execute_twice(authorized, fake_adapter, fake_adapter_state):
    engine, sealed, grant = authorized
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success
    with pytest.raises(GrantExhaustedError):
        engine.commit(sealed, grant, fake_adapter, context=None)
    assert len(fake_adapter_state.committed) == 1


def test_concurrent_commits_produce_at_most_one_success(
    authorized, fake_adapter_state, fixed_clock
):
    from karmasakshi.adapters.base import CommitResult, PreconditionResult

    engine, sealed, grant = authorized

    class SlowAdapter:
        adapter_id = "payment.simulator"
        adapter_version = "1.0.0"

        def validate_preconditions(self, manifest, context):
            return PreconditionResult(satisfied=True)

        def commit(self, manifest, grant, context):
            ref = f"ref-{len(fake_adapter_state.committed) + 1}"
            fake_adapter_state.committed.append({"manifest_id": manifest.manifest_id, "ref": ref})
            return CommitResult(
                success=True, idempotency_key=manifest.idempotency_key, provider_reference=ref
            )

        def prepare(self, request, context):
            return request

        def verify(self, manifest, commit_result, context):
            raise NotImplementedError

        def compensate(self, manifest, commit_result, context):
            raise NotImplementedError

    adapter = SlowAdapter()
    results: list[object] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def attempt():
        barrier.wait()
        try:
            results.append(engine.commit(sealed, grant, adapter, context=None))
        except Exception as exc:  # noqa: BLE001 - collecting whatever concurrent threads raise
            errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(fake_adapter_state.committed) == 1
    assert sum(1 for r in results if getattr(r, "success", False)) == 1
    assert len(errors) == 7
    assert all(isinstance(e, GrantExhaustedError) for e in errors)


def test_idempotent_retry_does_not_recommit(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
    fake_adapter_state,
):
    # Simulates a client-side retry of the *whole* propose->commit pipeline (e.g. after
    # a network timeout): a fresh manifest_id/nonce is resolved, but the idempotency_key
    # is stable across the retry because it represents the same real-world intent.
    engine = engine_factory()
    manifest1 = manifest_factory(manifest_id="retry-attempt-1", nonce="nonce-retry-1")
    sealed1 = _prepare_and_seal(engine, fake_adapter, manifest1, issuer_signing_key)
    grant1 = _authorize(
        engine,
        sealed1,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        grant_id="grant-retry-1",
        nonce="grant-nonce-retry-1",
    )
    result1 = engine.commit(sealed1, grant1, fake_adapter, context=None)
    assert result1.success
    assert len(fake_adapter_state.committed) == 1

    manifest2 = manifest_factory(manifest_id="retry-attempt-2", nonce="nonce-retry-2")
    assert manifest2.idempotency_key == manifest1.idempotency_key
    sealed2 = _prepare_and_seal(engine, fake_adapter, manifest2, issuer_signing_key)
    grant2 = _authorize(
        engine,
        sealed2,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        grant_id="grant-retry-2",
        nonce="grant-nonce-retry-2",
    )
    result2 = engine.commit(sealed2, grant2, fake_adapter, context=None)
    assert result2.success
    assert "idempotent replay" in (result2.detail or "")
    assert len(fake_adapter_state.committed) == 1


def test_store_multi_use_ceiling_allows_configured_number_of_uses():
    from karmasakshi.stores.memory import InMemoryGrantStore

    store = InMemoryGrantStore()
    assert store.reserve("g1", max_uses=2) is True
    store.commit("g1", "idem-1", "ref-1")
    assert store.get_use_count("g1") == 1

    assert store.reserve("g1", max_uses=2) is True
    store.commit("g1", "idem-2", "ref-2")
    assert store.get_use_count("g1") == 2

    # third use exceeds the configured ceiling
    assert store.reserve("g1", max_uses=2) is False


def test_store_failed_attempt_releases_without_consuming_a_use():
    from karmasakshi.stores.memory import InMemoryGrantStore

    store = InMemoryGrantStore()
    assert store.reserve("g1", max_uses=1) is True
    store.release("g1")
    assert store.get_use_count("g1") == 0
    # the released slot is available again
    assert store.reserve("g1", max_uses=1) is True


# --- assess() (Effect Intelligence Engine integration) -----------------------


def test_assess_records_an_audit_event(engine_factory, manifest_factory):
    from karmasakshi.intelligence import AssessmentFacts, Recommendation

    engine = engine_factory()
    manifest = manifest_factory()

    assessment = engine.assess(manifest, AssessmentFacts(historical_recurrence_count=1))

    events = engine.context.audit.events_for_manifest(manifest.manifest_id)
    assessed_events = [e for e in events if e.event_type == "effect.assessed"]
    assert len(assessed_events) == 1
    event = assessed_events[0]
    assert event.decision == assessment.recommendation.value
    assert event.manifest_hash == manifest.canonical_hash()
    assert event.metadata["assessment_id"] == assessment.assessment_id
    assert event.metadata["score"] == str(assessment.score)
    assert Recommendation(event.decision) == assessment.recommendation
    # verify_chain() must still pass -- assess() participates in the same
    # hash-chained journal as every other engine step.
    engine.context.audit.verify_chain()


def test_assess_does_not_transition_lifecycle_state(engine_factory, manifest_factory):
    from karmasakshi.state_machine.states import LifecycleState

    engine = engine_factory()
    manifest = manifest_factory()

    assert engine.get_lifecycle_state(manifest.manifest_id) == LifecycleState.PROPOSED
    engine.assess(manifest)
    assert engine.get_lifecycle_state(manifest.manifest_id) == LifecycleState.PROPOSED


def test_assess_can_be_called_multiple_times_with_different_facts(engine_factory, manifest_factory):
    from karmasakshi.intelligence import AssessmentFacts

    engine = engine_factory()
    manifest = manifest_factory()

    first = engine.assess(manifest, AssessmentFacts())
    second = engine.assess(manifest, AssessmentFacts(cross_tenant=True))

    assert first.assessment_id != second.assessment_id
    events = engine.context.audit.events_for_manifest(manifest.manifest_id)
    assert len([e for e in events if e.event_type == "effect.assessed"]) == 2


def test_assess_uses_context_configured_policy(
    engine_factory, manifest_factory, keyring, fixed_clock
):
    from karmasakshi.audit.journal import AuditJournal
    from karmasakshi.engine.context import EngineContext
    from karmasakshi.engine.core import KarmaSakshiEngine
    from karmasakshi.intelligence import EffectIntelligenceEngine, IntelligencePolicy
    from karmasakshi.stores.memory import InMemoryGrantStore

    strict_policy = IntelligencePolicy(restricted_effect_types=("payment.transfer",))
    ctx = EngineContext(
        keyring=keyring,
        grant_store=InMemoryGrantStore(),
        audit=AuditJournal(clock=fixed_clock),
        clock=fixed_clock,
        intelligence=EffectIntelligenceEngine(policy=strict_policy),
    )
    engine = KarmaSakshiEngine(ctx)
    manifest = manifest_factory(effect_type="payment.transfer")

    assessment = engine.assess(manifest)

    from karmasakshi.intelligence import Recommendation

    assert assessment.recommendation == Recommendation.BLOCK
    assert assessment.policy_id == strict_policy.policy_id


# --- signed policy bundles (extreme-v2 Phase 2) -------------------------------


def _sealed_bundle(signing_key, now, *, bundle_id="bundle-1", block_threshold=85):
    from karmasakshi.config.clock import FixedClock
    from karmasakshi.domain.common import Principal
    from karmasakshi.domain.enums import PrincipalType
    from karmasakshi.intelligence import IntelligencePolicy
    from karmasakshi.intelligence.policy import build_policy_bundle
    from karmasakshi.policy import seal_policy_bundle

    bundle = build_policy_bundle(
        IntelligencePolicy(
            block_threshold=block_threshold, review_threshold=min(1, block_threshold)
        ),
        bundle_id=bundle_id,
        bundle_version="1.0",
        issuer=Principal(principal_id="policy-admin", principal_type=PrincipalType.HUMAN),
        created_at=now,
        effective_from=now,
    )
    return seal_policy_bundle(bundle, signing_key, clock=FixedClock(now))


def test_authorize_with_policy_bundle_binds_hash_into_grant(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    sealed_bundle = _sealed_bundle(issuer_signing_key, now)

    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        policy_bundle=sealed_bundle,
    )
    assert grant.policy_bundle_hash == sealed_bundle.seal.bundle_hash


def test_commit_with_matching_policy_bundle_succeeds(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    sealed_bundle = _sealed_bundle(issuer_signing_key, now)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        policy_bundle=sealed_bundle,
    )
    result = engine.commit(sealed, grant, fake_adapter, context=None, policy_bundle=sealed_bundle)
    assert result.success


def test_commit_missing_required_policy_bundle_is_rejected(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    from karmasakshi.errors import PolicyBundleMismatchError

    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    sealed_bundle = _sealed_bundle(issuer_signing_key, now)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        policy_bundle=sealed_bundle,
    )
    with pytest.raises(PolicyBundleMismatchError):
        engine.commit(sealed, grant, fake_adapter, context=None)


def test_commit_with_swapped_policy_bundle_is_rejected(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    """The core Phase 2 security property: a policy edit/swap between
    authorize() and commit() must never silently change what was
    approved -- committing against a *different*, validly-signed policy
    bundle than the one bound into the grant must fail closed."""
    from karmasakshi.errors import PolicyBundleMismatchError

    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    original_bundle = _sealed_bundle(
        issuer_signing_key, now, bundle_id="original", block_threshold=85
    )
    swapped_bundle = _sealed_bundle(issuer_signing_key, now, bundle_id="swapped", block_threshold=1)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        policy_bundle=original_bundle,
    )
    with pytest.raises(PolicyBundleMismatchError):
        engine.commit(sealed, grant, fake_adapter, context=None, policy_bundle=swapped_bundle)


def test_commit_with_tampered_policy_bundle_is_rejected(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    from karmasakshi.errors import PolicyBundleTamperedError

    engine = engine_factory()
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    sealed_bundle = _sealed_bundle(issuer_signing_key, now)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        policy_bundle=sealed_bundle,
    )
    tampered_inner = sealed_bundle.bundle.model_copy(
        update={"payload": {**sealed_bundle.bundle.payload, "block_threshold": 1}}
    )
    tampered = sealed_bundle.model_copy(update={"bundle": tampered_inner})
    with pytest.raises(PolicyBundleTamperedError):
        engine.commit(sealed, grant, fake_adapter, context=None, policy_bundle=tampered)


def test_commit_without_bound_policy_bundle_is_unaffected_by_extra_bundle(
    authorized, fake_adapter, issuer_signing_key, now
):
    """Backward compatibility: a grant issued without a policy bundle
    (``policy_bundle_hash is None``) must commit exactly as before, even
    if the caller happens to pass an (irrelevant) policy_bundle."""
    engine, sealed, grant = authorized
    assert grant.policy_bundle_hash is None
    sealed_bundle = _sealed_bundle(issuer_signing_key, now)
    result = engine.commit(sealed, grant, fake_adapter, context=None, policy_bundle=sealed_bundle)
    assert result.success


# --- multi-party (M-of-N) authorization (extreme-v2 Phase 3) -----------------


def _quorum_engine(fixed_clock, *keys):
    from karmasakshi.audit.journal import AuditJournal
    from karmasakshi.crypto import Keyring
    from karmasakshi.engine.context import EngineContext
    from karmasakshi.engine.core import KarmaSakshiEngine
    from karmasakshi.stores.memory import InMemoryGrantStore

    ctx = EngineContext(
        keyring=Keyring([k.verification_key() for k in keys]),
        grant_store=InMemoryGrantStore(),
        audit=AuditJournal(clock=fixed_clock),
        clock=fixed_clock,
    )
    return KarmaSakshiEngine(ctx)


def _sealed_approval_bundle(
    signing_key, now, *, bundle_id="approval-bundle-1", required_approvals=2
):
    from karmasakshi.approval import ApprovalPolicy, build_approval_policy_bundle
    from karmasakshi.config.clock import FixedClock
    from karmasakshi.domain.common import Principal
    from karmasakshi.domain.enums import PrincipalType
    from karmasakshi.policy import seal_policy_bundle

    bundle = build_approval_policy_bundle(
        ApprovalPolicy(required_approvals=required_approvals),
        bundle_id=bundle_id,
        bundle_version="1.0",
        issuer=Principal(principal_id="policy-admin", principal_type=PrincipalType.HUMAN),
        created_at=now,
        effective_from=now,
    )
    return seal_policy_bundle(bundle, signing_key, clock=FixedClock(now))


def _approval(key, name, sealed, approval_bundle, now, *, decision="approve"):
    from karmasakshi.approval import sign_approval_statement
    from karmasakshi.config.clock import FixedClock
    from karmasakshi.domain.common import Principal

    return sign_approval_statement(
        statement_id=f"stmt-{name}",
        manifest_hash=sealed.seal.manifest_hash,
        approval_policy_bundle_hash=approval_bundle.seal.bundle_hash,
        approver=Principal(principal_id=name, principal_type=PrincipalType.HUMAN),
        decision=decision,
        signing_key=key,
        expires_at=now + timedelta(minutes=30),
        nonce=f"nonce-{name}",
        clock=FixedClock(now),
    )


def test_authorize_with_quorum_succeeds_with_enough_approvals(
    manifest_factory, agent_principal, issuer_signing_key, fixed_clock, now, fake_adapter
):
    from karmasakshi.domain.common import Principal
    from karmasakshi.grants.model import ScopeConstraints

    alice_key = other_signing_key_factory("alice")
    bob_key = other_signing_key_factory("bob")
    engine = _quorum_engine(fixed_clock, issuer_signing_key, alice_key, bob_key)
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    approval_bundle = _sealed_approval_bundle(issuer_signing_key, now, required_approvals=2)
    statements = (
        _approval(alice_key, "alice", sealed, approval_bundle, now),
        _approval(bob_key, "bob", sealed, approval_bundle, now),
    )
    grant = engine.authorize_with_quorum(
        sealed,
        statements=statements,
        approval_policy_bundle=approval_bundle,
        proposer=manifest.actor,
        subject=agent_principal,
        grant_issuer=Principal(principal_id="quorum-service", principal_type=PrincipalType.SERVICE),
        audience=("payment.simulator",),
        allowed_effect_types=(manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    assert grant.approval_set_hash is not None
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success


def test_authorize_with_quorum_raises_when_quorum_not_met(
    manifest_factory, agent_principal, issuer_signing_key, fixed_clock, now, fake_adapter
):
    from karmasakshi.domain.common import Principal
    from karmasakshi.errors import QuorumNotMetError
    from karmasakshi.grants.model import ScopeConstraints

    alice_key = other_signing_key_factory("alice")
    engine = _quorum_engine(fixed_clock, issuer_signing_key, alice_key)
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    approval_bundle = _sealed_approval_bundle(issuer_signing_key, now, required_approvals=2)
    statements = (_approval(alice_key, "alice", sealed, approval_bundle, now),)

    with pytest.raises(QuorumNotMetError):
        engine.authorize_with_quorum(
            sealed,
            statements=statements,
            approval_policy_bundle=approval_bundle,
            proposer=manifest.actor,
            subject=agent_principal,
            grant_issuer=Principal(
                principal_id="quorum-service", principal_type=PrincipalType.SERVICE
            ),
            audience=("payment.simulator",),
            allowed_effect_types=(manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            signing_key=issuer_signing_key,
        )


def test_authorize_with_quorum_rejects_dissent_veto(
    manifest_factory, agent_principal, issuer_signing_key, fixed_clock, now, fake_adapter
):
    from karmasakshi.domain.common import Principal
    from karmasakshi.errors import QuorumNotMetError
    from karmasakshi.grants.model import ScopeConstraints

    alice_key = other_signing_key_factory("alice")
    bob_key = other_signing_key_factory("bob")
    engine = _quorum_engine(fixed_clock, issuer_signing_key, alice_key, bob_key)
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    approval_bundle = _sealed_approval_bundle(issuer_signing_key, now, required_approvals=1)
    statements = (
        _approval(alice_key, "alice", sealed, approval_bundle, now, decision="approve"),
        _approval(bob_key, "bob", sealed, approval_bundle, now, decision="dissent"),
    )
    with pytest.raises(QuorumNotMetError):
        engine.authorize_with_quorum(
            sealed,
            statements=statements,
            approval_policy_bundle=approval_bundle,
            proposer=manifest.actor,
            subject=agent_principal,
            grant_issuer=Principal(
                principal_id="quorum-service", principal_type=PrincipalType.SERVICE
            ),
            audience=("payment.simulator",),
            allowed_effect_types=(manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            signing_key=issuer_signing_key,
        )


def test_authorize_with_quorum_grant_commits_without_re_presenting_approvals(
    manifest_factory, agent_principal, issuer_signing_key, fixed_clock, now, fake_adapter
):
    """The approval set is validated once at authorize time; commit()
    does not require the statements to be re-presented (unlike policy
    bundles) -- see the docstring on authorize_with_quorum for why."""
    from karmasakshi.domain.common import Principal
    from karmasakshi.grants.model import ScopeConstraints

    alice_key = other_signing_key_factory("alice")
    engine = _quorum_engine(fixed_clock, issuer_signing_key, alice_key)
    manifest = manifest_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest, issuer_signing_key)
    approval_bundle = _sealed_approval_bundle(issuer_signing_key, now, required_approvals=1)
    statements = (_approval(alice_key, "alice", sealed, approval_bundle, now),)
    grant = engine.authorize_with_quorum(
        sealed,
        statements=statements,
        approval_policy_bundle=approval_bundle,
        proposer=manifest.actor,
        subject=agent_principal,
        grant_issuer=Principal(principal_id="quorum-service", principal_type=PrincipalType.SERVICE),
        audience=("payment.simulator",),
        allowed_effect_types=(manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    # No `statements=` kwarg accepted by commit() at all -- proves the grant
    # alone (plus its cryptographic approval_set_hash) is sufficient.
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success
