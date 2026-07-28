from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.passports import build_passport, render_passport_html, render_passport_markdown


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
def full_run(
    engine_factory,
    manifest_factory,
    fake_adapter,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="passport-1")
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )
    commit_result = engine.commit(sealed, grant, fake_adapter, context=None)
    outcome_proof = engine.verify(sealed.manifest, commit_result, fake_adapter, context=None)
    return engine, sealed, grant, commit_result, outcome_proof


def test_passport_reflects_successful_commit_and_verification(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    passport = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    assert passport.commit_success is True
    assert passport.observed_matched_expected is True
    assert passport.verification.seal_verified is True
    assert passport.verification.grant_verified is True
    assert passport.verification.audit_chain_verified is True
    assert passport.was_revoked is False
    assert passport.grant_id == grant.grant_id


def test_passport_reflects_revoked_grant(full_run, keyring, human_principal):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    engine.context.grant_store.revoke(grant.grant_id)
    passport = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    assert passport.was_revoked is True


def test_passport_without_grant_reflects_unauthorized_state(
    engine_factory, manifest_factory, fake_adapter, keyring, issuer_signing_key
):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="passport-2")
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    passport = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
    )
    assert passport.grant_id is None
    assert passport.authorized_by is None
    assert passport.was_revoked is False
    assert passport.commit_attempted is False
    assert passport.verification.seal_verified is True


def test_passport_detects_tampered_manifest(full_run, keyring, manifest_factory):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    tampered_manifest = manifest_factory(
        manifest_id=sealed.manifest.manifest_id, target_resource="payment:beneficiary/ATTACKER"
    )
    tampered_sealed = sealed.model_copy(update={"manifest": tampered_manifest})
    passport = build_passport(
        sealed=tampered_sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    assert passport.verification.seal_verified is False


def test_render_markdown_contains_key_facts(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    passport = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    md = render_passport_markdown(passport)
    assert passport.manifest_id in md
    assert passport.manifest_hash in md
    assert "not a security certification" in md


def test_render_html_escapes_and_wraps(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    passport = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    out = render_passport_html(passport)
    assert "<article" in out
    assert passport.manifest_id in out


def test_passport_json_roundtrip(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    passport = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    from karmasakshi.passports.model import ActionPassport

    data = passport.model_dump_json()
    restored = ActionPassport.model_validate_json(data)
    assert restored == passport
