from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.errors import (
    EvidencePackAssemblyError,
    EvidencePackTooLargeError,
    ManifestTamperedError,
)
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.passports import build_passport_v2
from karmasakshi.portable import (
    EVIDENCE_PACK_FORMAT,
    EvidencePack,
    build_evidence_pack,
    verify_evidence_pack,
)


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
    manifest = manifest_factory(manifest_id="evidence-pack-1")
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


def _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring):
    passport = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
        tenant_id="tenant-a",
    )
    return build_evidence_pack(
        passport=passport,
        sealed_manifest=sealed,
        audit=engine.context.audit,
        keyring=keyring,
        grant=grant,
    )


def test_build_and_verify_round_trip(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    assert pack.pack_format == EVIDENCE_PACK_FORMAT
    assert pack.schema_version == "1.0"
    assert pack.manifest_id == sealed.manifest.manifest_id
    assert pack.pack_hash.startswith("sha256:")
    assert len(pack.audit_events) > 0
    assert len(pack.verification_keys) == 1

    result = verify_evidence_pack(pack)
    assert result.all_verified is True
    assert result.reasons == ()


def test_pack_round_trips_through_json(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    raw = pack.model_dump_json()
    reloaded = EvidencePack.model_validate_json(raw)
    assert reloaded == pack
    result = verify_evidence_pack(reloaded)
    assert result.all_verified is True


def test_tampered_pack_hash_detected(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    tampered = pack.model_copy(update={"pack_hash": "sha256:" + ("0" * 64)})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.pack_hash_verified is False
    assert any("pack_hash" in r for r in result.reasons)


def test_tampered_passport_content_detected(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    tampered_passport = pack.passport.model_copy(update={"target_resource": "payment:attacker"})
    tampered = pack.model_copy(update={"passport": tampered_passport})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.passport_hash_verified is False
    with pytest.raises(ManifestTamperedError):
        tampered.passport.verify_passport_hash()


def test_tampered_sealed_manifest_detected(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    tampered_manifest = pack.sealed_manifest.manifest.model_copy(
        update={"target_resource": "payment:attacker"}
    )
    tampered_sealed = pack.sealed_manifest.model_copy(update={"manifest": tampered_manifest})
    tampered = pack.model_copy(update={"sealed_manifest": tampered_sealed})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.seal_verified is False


def test_forged_signature_over_correct_hash_rejected(full_run, keyring, other_signing_key):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    forged_signature = other_signing_key.sign(sealed.seal.manifest_hash.encode("utf-8"))
    tampered_seal = pack.sealed_manifest.seal.model_copy(update={"signature": forged_signature})
    tampered_sealed = pack.sealed_manifest.model_copy(update={"seal": tampered_seal})
    tampered = pack.model_copy(update={"sealed_manifest": tampered_sealed})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.seal_verified is False


def test_removed_verification_key_fails_closed(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    tampered = pack.model_copy(update={"verification_keys": ()})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.seal_verified is False


def test_tampered_audit_event_detected(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    events = list(pack.audit_events)
    events[0] = events[0].model_copy(update={"decision": "tampered"})
    tampered = pack.model_copy(update={"audit_events": tuple(events)})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.audit_events_self_consistent is False


def test_reordered_audit_events_detected(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)
    assert len(pack.audit_events) >= 2

    reversed_events = tuple(reversed(pack.audit_events))
    tampered = pack.model_copy(update={"audit_events": reversed_events})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.audit_events_self_consistent is False


def test_audit_event_for_different_manifest_detected(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    foreign_event = pack.audit_events[0].model_copy(update={"manifest_id": "some-other-manifest"})
    tampered = pack.model_copy(update={"audit_events": (*pack.audit_events, foreign_event)})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.audit_events_match_manifest is False


def test_grant_manifest_hash_swapped_detected(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)
    assert pack.grant is not None

    swapped_grant = pack.grant.model_copy(update={"manifest_hash": "sha256:" + ("f" * 64)})
    tampered = pack.model_copy(update={"grant": swapped_grant})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.manifest_hash_consistent is False


def test_no_grant_pack_is_still_verifiable(
    engine_factory, manifest_factory, fake_adapter, issuer_signing_key, keyring
):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="evidence-pack-no-grant")
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    passport = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(manifest.manifest_id).value,
    )
    pack = build_evidence_pack(
        passport=passport,
        sealed_manifest=sealed,
        audit=engine.context.audit,
        keyring=keyring,
    )
    assert pack.grant is None
    result = verify_evidence_pack(pack)
    assert result.all_verified is True


def test_build_rejects_manifest_id_mismatch(
    full_run, keyring, manifest_factory, fake_adapter, issuer_signing_key
):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    passport = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    other_manifest = manifest_factory(manifest_id="a-different-manifest")
    other_prepared = engine.prepare(fake_adapter, other_manifest, context=None)
    other_sealed = engine.seal(other_prepared, issuer_signing_key)

    with pytest.raises(EvidencePackAssemblyError):
        build_evidence_pack(
            passport=passport,
            sealed_manifest=other_sealed,
            audit=engine.context.audit,
            keyring=keyring,
        )


def test_build_rejects_grant_manifest_hash_mismatch(
    full_run, keyring, manifest_factory, fake_adapter, issuer_signing_key
):
    engine, _sealed, grant, _commit_result, _outcome_proof = full_run
    other_manifest = manifest_factory(manifest_id="a-different-manifest-2")
    other_prepared = engine.prepare(fake_adapter, other_manifest, context=None)
    other_sealed = engine.seal(other_prepared, issuer_signing_key)
    passport = build_passport_v2(
        sealed=other_sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(other_manifest.manifest_id).value,
    )

    with pytest.raises(EvidencePackAssemblyError):
        build_evidence_pack(
            passport=passport,
            sealed_manifest=other_sealed,
            audit=engine.context.audit,
            keyring=keyring,
            grant=grant,
        )


def test_build_rejects_oversized_audit_slice(full_run, keyring, monkeypatch):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    passport = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    monkeypatch.setattr(
        "karmasakshi.portable.builder.MAX_EMBEDDED_AUDIT_EVENTS",
        0,
    )
    with pytest.raises(EvidencePackTooLargeError):
        build_evidence_pack(
            passport=passport,
            sealed_manifest=sealed,
            audit=engine.context.audit,
            keyring=keyring,
            grant=grant,
        )


def test_build_rejects_oversized_keyring(full_run, keyring, monkeypatch):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    passport = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    monkeypatch.setattr(
        "karmasakshi.portable.builder.MAX_EMBEDDED_KEYS",
        0,
    )
    with pytest.raises(EvidencePackTooLargeError):
        build_evidence_pack(
            passport=passport,
            sealed_manifest=sealed,
            audit=engine.context.audit,
            keyring=keyring,
            grant=grant,
        )


def test_malformed_embedded_key_fails_closed_not_crash(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    pack = _build_pack(engine, sealed, grant, commit_result, outcome_proof, keyring)

    bad_key = pack.verification_keys[0].model_copy(update={"public_key_b64": "not-valid-base64!!!"})
    tampered = pack.model_copy(update={"verification_keys": (bad_key,)})
    result = verify_evidence_pack(tampered)
    assert result.all_verified is False
    assert result.seal_verified is False
    assert any("verification_keys" in r for r in result.reasons)
