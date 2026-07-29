"""Adversarial tests for compensation binding and passport separation."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.compensation import (
    build_compensation_manifest,
    build_compensation_passport,
)
from karmasakshi.errors import CompensationBindingError, GrantIssuerNotAuthorizedError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.passports import build_passport


def _prepare_and_seal(engine, adapter, manifest, signing_key):
    prepared = engine.prepare(adapter, manifest, context=None)
    return engine.seal(prepared, signing_key)


def test_grafted_original_hash_in_parameters_is_rejected(
    engine_factory, manifest_factory, fake_adapter, issuer_signing_key
):
    engine = engine_factory()
    original = _prepare_and_seal(engine, fake_adapter, manifest_factory(), issuer_signing_key)
    with pytest.raises(CompensationBindingError, match="conflicts"):
        build_compensation_manifest(
            original=original,
            parameters={"original_manifest_hash": "sha256:" + "0" * 64},
        )


def test_agent_cannot_authorize_compensation(
    engine_factory,
    manifest_factory,
    fake_adapter,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    original = _prepare_and_seal(engine, fake_adapter, manifest_factory(), issuer_signing_key)
    comp = build_compensation_manifest(original=original)
    engine.prepare_compensation(comp, original_sealed=original)
    sealed = engine.seal(comp, issuer_signing_key)
    with pytest.raises(GrantIssuerNotAuthorizedError):
        engine.authorize_compensation(
            original,
            sealed,
            issuer=agent_principal,
            subject=agent_principal,
            audience=(fake_adapter.adapter_id,),
            allowed_effect_types=(sealed.manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            signing_key=issuer_signing_key,
        )


def test_building_compensation_passport_does_not_alter_action_passport(
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
    action = build_passport(
        sealed=original,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state="verified",
        grant=grant,
        commit_result=commit_result,
    )
    before = action.model_dump_json()

    comp = build_compensation_manifest(original=original, original_commit=commit_result)
    engine.prepare_compensation(comp, original_sealed=original)
    sealed = engine.seal(comp, issuer_signing_key)
    build_compensation_passport(
        compensation_sealed=sealed,
        original_sealed=original,
        keyring=keyring,
        audit=engine.context.audit,
    )
    assert action.model_dump_json() == before
