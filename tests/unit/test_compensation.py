"""Unit tests for compensation manifests and Compensation Passports."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.adapters.base import CompensationResult
from karmasakshi.compensation import (
    CompensationPassport,
    CompensationStatus,
    assert_compensation_binds_original,
    build_compensation_manifest,
    build_compensation_passport,
    derive_compensation_status,
    original_manifest_hash_of,
)
from karmasakshi.errors import CompensationBindingError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.passports import build_passport
from karmasakshi.state_machine import LifecycleState


def _prepare_and_seal(engine, adapter, manifest, signing_key):
    prepared = engine.prepare(adapter, manifest, context=None)
    return engine.seal(prepared, signing_key)


def test_build_compensation_manifest_binds_original_hash(
    engine_factory, manifest_factory, fake_adapter, issuer_signing_key
):
    engine = engine_factory()
    original = _prepare_and_seal(engine, fake_adapter, manifest_factory(), issuer_signing_key)
    comp = build_compensation_manifest(original=original)
    assert original_manifest_hash_of(comp) == original.seal.manifest_hash
    assert comp.parent_manifest_id == original.manifest.manifest_id
    assert_compensation_binds_original(comp, original)


def test_binding_rejects_wrong_original(
    engine_factory, manifest_factory, fake_adapter, issuer_signing_key
):
    engine = engine_factory()
    a = _prepare_and_seal(
        engine, fake_adapter, manifest_factory(idempotency_key="a", nonce="na"), issuer_signing_key
    )
    b = _prepare_and_seal(
        engine,
        fake_adapter,
        manifest_factory(
            idempotency_key="b",
            nonce="nb",
            manifest_id="22222222-2222-4222-8222-222222222222",
        ),
        issuer_signing_key,
    )
    comp = build_compensation_manifest(original=a)
    with pytest.raises(CompensationBindingError):
        assert_compensation_binds_original(comp, b)


def test_derive_status_triad():
    assert (
        derive_compensation_status(
            adapter_result=CompensationResult(
                attempted=False, succeeded=False, reason="irreversible"
            )
        )
        == CompensationStatus.REFUSED
    )
    assert (
        derive_compensation_status(
            adapter_result=CompensationResult(attempted=True, succeeded=True)
        )
        == CompensationStatus.ATTEMPTED
    )
    from datetime import datetime, timezone

    from karmasakshi.adapters.base import OutcomeProof

    proof = OutcomeProof(matched_expected=True, observed_at=datetime.now(timezone.utc))
    assert (
        derive_compensation_status(
            adapter_result=CompensationResult(attempted=True, succeeded=True),
            outcome_proof=proof,
        )
        == CompensationStatus.VERIFIED
    )


def test_authorized_compensation_path_and_separate_passport(
    engine_factory,
    manifest_factory,
    fake_adapter,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
    keyring,
):
    engine = engine_factory()
    original = _prepare_and_seal(engine, fake_adapter, manifest_factory(), issuer_signing_key)
    grant = engine.authorize(
        original,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(original.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    commit_result = engine.commit(original, grant, fake_adapter, context=None)
    assert commit_result.success
    engine.verify(original.manifest, commit_result, fake_adapter, context=None)

    original_passport = build_passport(
        sealed=original,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(original.manifest.manifest_id).value,
        grant=grant,
        commit_result=commit_result,
    )
    snapshot = original_passport.model_dump()

    comp_manifest = build_compensation_manifest(original=original, original_commit=commit_result)
    engine.prepare_compensation(comp_manifest, original_sealed=original)
    comp_sealed = engine.seal(comp_manifest, issuer_signing_key)
    comp_grant = engine.authorize_compensation(
        original,
        comp_sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(comp_sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    comp_commit = engine.commit_compensation(
        original,
        comp_sealed,
        comp_grant,
        fake_adapter,
        context=None,
        original_commit=commit_result,
    )
    assert comp_commit.success
    assert engine.get_lifecycle_state(original.manifest.manifest_id) == LifecycleState.COMPENSATED

    comp_passport = build_compensation_passport(
        compensation_sealed=comp_sealed,
        original_sealed=original,
        keyring=keyring,
        audit=engine.context.audit,
        grant=comp_grant,
        commit_result=comp_commit,
    )
    assert isinstance(comp_passport, CompensationPassport)
    assert comp_passport.status == CompensationStatus.ATTEMPTED
    assert comp_passport.original_manifest_hash == original.seal.manifest_hash

    # Original Action Passport object is unchanged (never mutated in place).
    assert original_passport.model_dump() == snapshot
    assert original_passport.compensation_manifest_hash is None


def test_authorize_compensation_rejects_unbound_manifest(
    engine_factory,
    manifest_factory,
    fake_adapter,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    a = _prepare_and_seal(
        engine, fake_adapter, manifest_factory(idempotency_key="a", nonce="na"), issuer_signing_key
    )
    b = _prepare_and_seal(
        engine,
        fake_adapter,
        manifest_factory(
            idempotency_key="b",
            nonce="nb",
            manifest_id="22222222-2222-4222-8222-222222222222",
        ),
        issuer_signing_key,
    )
    comp = build_compensation_manifest(original=a)
    engine.prepare_compensation(comp, original_sealed=a)
    sealed = engine.seal(comp, issuer_signing_key)
    with pytest.raises(CompensationBindingError):
        engine.authorize_compensation(
            b,
            sealed,
            issuer=human_principal,
            subject=agent_principal,
            audience=(fake_adapter.adapter_id,),
            allowed_effect_types=(sealed.manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            signing_key=issuer_signing_key,
        )


def test_legacy_compensate_still_works(
    engine_factory,
    manifest_factory,
    fake_adapter,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    original = _prepare_and_seal(engine, fake_adapter, manifest_factory(), issuer_signing_key)
    grant = engine.authorize(
        original,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(original.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    commit_result = engine.commit(original, grant, fake_adapter, context=None)
    engine.verify(original.manifest, commit_result, fake_adapter, context=None)
    result = engine.compensate(original.manifest, commit_result, fake_adapter, context=None)
    assert result.attempted is True
    assert result.succeeded is True
