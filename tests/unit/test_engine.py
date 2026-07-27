from __future__ import annotations

import threading
from datetime import timedelta

import pytest

from chitragupta.errors import (
    AdapterMismatchError,
    GrantAudienceError,
    GrantExhaustedError,
    GrantExpiredError,
    GrantManifestMismatchError,
    GrantRevokedError,
    ManifestTamperedError,
    StaleManifestError,
)
from chitragupta.grants.model import ScopeConstraints
from chitragupta.state_machine import LifecycleState


def _prepare_and_seal(engine, adapter, manifest, signing_key):
    prepared = engine.prepare(adapter, manifest, context=None)
    return engine.seal(prepared, signing_key)


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
    from chitragupta.adapters.base import CommitResult, PreconditionResult

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
        except Exception as exc:
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
    from chitragupta.stores.memory import InMemoryGrantStore

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
    from chitragupta.stores.memory import InMemoryGrantStore

    store = InMemoryGrantStore()
    assert store.reserve("g1", max_uses=1) is True
    store.release("g1")
    assert store.get_use_count("g1") == 0
    # the released slot is available again
    assert store.reserve("g1", max_uses=1) is True
