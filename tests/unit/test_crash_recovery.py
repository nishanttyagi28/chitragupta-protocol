from __future__ import annotations

from datetime import timedelta

from chitragupta.grants.model import ScopeConstraints


def _prepare_seal_authorize(
    engine, adapter, manifest, *, issuer, subject, issuer_signing_key, now, grant_id, nonce
):
    prepared = engine.prepare(adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=issuer,
        subject=subject,
        audience=("payment.simulator",),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
        grant_id=grant_id,
        nonce=nonce,
    )
    return sealed, grant


def test_ambiguous_recovery_detects_effect_that_already_happened(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="crash-1", idempotency_key="idem-crash-1")

    # Simulate: the adapter's external effect already happened (e.g. payment
    # provider received and processed the request), but the process crashed
    # before chitragupta's local store could finalize the reservation --
    # bypass engine.commit() entirely to model that ambiguity.
    fake_adapter.commit(manifest, grant=None, context=None)
    assert len(fake_adapter_state.committed) == 1

    proof = engine.recover_ambiguous_commit(manifest, fake_adapter, context=None)
    assert proof.matched_expected

    # A fresh authorization + commit attempt must now take the idempotent
    # replay path instead of re-invoking the adapter.
    sealed, grant = _prepare_seal_authorize(
        engine,
        fake_adapter,
        manifest,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        grant_id="grant-crash-1",
        nonce="nonce-grant-crash-1",
    )
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success
    assert "idempotent replay" in (result.detail or "")
    assert len(fake_adapter_state.committed) == 1  # adapter was not called again


def test_ambiguous_recovery_finds_no_evidence_allows_fresh_commit(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="crash-2", idempotency_key="idem-crash-2")

    # Nothing happened externally yet (e.g. the process crashed before even
    # reaching the adapter).
    proof = engine.recover_ambiguous_commit(manifest, fake_adapter, context=None)
    assert not proof.matched_expected
    assert engine.context.grant_store.get_idempotent_outcome("idem-crash-2") is None

    sealed, grant = _prepare_seal_authorize(
        engine,
        fake_adapter,
        manifest,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
        grant_id="grant-crash-2",
        nonce="nonce-grant-crash-2",
    )
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success
    assert "idempotent replay" not in (result.detail or "")
    assert len(fake_adapter_state.committed) == 1
