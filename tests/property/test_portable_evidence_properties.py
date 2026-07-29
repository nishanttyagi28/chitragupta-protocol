from __future__ import annotations

from datetime import timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.passports import build_passport_v2
from karmasakshi.portable import build_evidence_pack, verify_evidence_pack


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


@given(amount=st.integers(min_value=1, max_value=10_000_000))
@settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_untampered_pack_always_verifies(
    amount,
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    service_principal,
    agent_principal,
    now,
):
    engine = engine_factory()
    manifest = manifest_factory(
        manifest_id=f"prop-pack-{amount}",
        idempotency_key=f"idem-prop-{amount}",
        amount_minor_units=amount,
    )
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
    passport = build_passport_v2(
        sealed=sealed,
        keyring=engine.context.keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    pack = build_evidence_pack(
        passport=passport,
        sealed_manifest=sealed,
        audit=engine.context.audit,
        keyring=engine.context.keyring,
        grant=grant,
    )
    result = verify_evidence_pack(pack)
    assert result.all_verified is True
    # Verification is pure: calling it again gives the identical verdict.
    assert verify_evidence_pack(pack) == result


@given(garbage=st.text(min_size=1, max_size=64))
@settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_verify_never_raises_on_malformed_embedded_key(
    garbage,
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="prop-pack-badkey", idempotency_key="idem-prop-badkey")
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    passport = build_passport_v2(
        sealed=sealed,
        keyring=engine.context.keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
    )
    pack = build_evidence_pack(
        passport=passport,
        sealed_manifest=sealed,
        audit=engine.context.audit,
        keyring=engine.context.keyring,
    )
    bad_key = pack.verification_keys[0].model_copy(update={"public_key_b64": garbage})
    tampered = pack.model_copy(update={"verification_keys": (bad_key,)})
    # Must never raise, regardless of how malformed the embedded key text is.
    result = verify_evidence_pack(tampered)
    assert isinstance(result.all_verified, bool)
