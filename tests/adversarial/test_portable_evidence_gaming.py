"""Adversarial tests for portable Evidence Packs (extreme-v2 Phase 24).

These exercise cross-pack "frankenstein" assembly (mixing real components
from two different, independently valid packs) rather than single-field
tampering (covered in tests/unit/test_portable_evidence.py), plus what
offline verification explicitly does *not* prove.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.errors import SchemaVersionError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.passports import build_passport_v2
from karmasakshi.portable import EvidencePack, build_evidence_pack, verify_evidence_pack


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


def _full_pack(
    engine, manifest, *, fake_adapter, issuer_signing_key, service_principal, agent_principal, now
):
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
    return sealed, grant, pack


def test_cross_pack_sealed_manifest_splice_rejected(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    service_principal,
    agent_principal,
    now,
):
    """Splicing a wholesale sealed_manifest+grant from a *different*, fully
    valid pack into another pack's passport must be rejected -- each
    component being individually authentic is not enough; they must all
    reference the same manifest hash."""
    engine = engine_factory()
    manifest_a = manifest_factory(manifest_id="frankenstein-a", idempotency_key="idem-fr-a")
    manifest_b = manifest_factory(manifest_id="frankenstein-b", idempotency_key="idem-fr-b")

    _, _, pack_a = _full_pack(
        engine,
        manifest_a,
        fake_adapter=fake_adapter,
        issuer_signing_key=issuer_signing_key,
        service_principal=service_principal,
        agent_principal=agent_principal,
        now=now,
    )
    sealed_b, grant_b, _ = _full_pack(
        engine,
        manifest_b,
        fake_adapter=fake_adapter,
        issuer_signing_key=issuer_signing_key,
        service_principal=service_principal,
        agent_principal=agent_principal,
        now=now,
    )

    spliced = pack_a.model_copy(update={"sealed_manifest": sealed_b, "grant": grant_b})
    result = verify_evidence_pack(spliced)
    assert result.all_verified is False
    assert result.manifest_hash_consistent is False


def test_cross_pack_audit_slice_splice_rejected(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    service_principal,
    agent_principal,
    now,
):
    """Grafting another manifest's real (validly hash-chained) audit slice
    onto this pack must be caught by the manifest_id cross-check, not
    silently accepted just because the events are individually authentic."""
    engine = engine_factory()
    manifest_a = manifest_factory(manifest_id="frankenstein-c", idempotency_key="idem-fr-c")
    manifest_b = manifest_factory(manifest_id="frankenstein-d", idempotency_key="idem-fr-d")

    _, _, pack_a = _full_pack(
        engine,
        manifest_a,
        fake_adapter=fake_adapter,
        issuer_signing_key=issuer_signing_key,
        service_principal=service_principal,
        agent_principal=agent_principal,
        now=now,
    )
    _, _, pack_b = _full_pack(
        engine,
        manifest_b,
        fake_adapter=fake_adapter,
        issuer_signing_key=issuer_signing_key,
        service_principal=service_principal,
        agent_principal=agent_principal,
        now=now,
    )

    spliced = pack_a.model_copy(update={"audit_events": pack_b.audit_events})
    result = verify_evidence_pack(spliced)
    assert result.all_verified is False
    assert result.audit_events_match_manifest is False


def test_downgraded_schema_version_rejected_at_parse_time(full_run_json_payload) -> None:
    payload = dict(full_run_json_payload)
    payload["schema_version"] = "0.9"
    with pytest.raises(SchemaVersionError):
        EvidencePack.model_validate(payload)


@pytest.fixture
def full_run_json_payload(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    service_principal,
    agent_principal,
    now,
):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="frankenstein-schema", idempotency_key="idem-fr-schema")
    _, _, pack = _full_pack(
        engine,
        manifest,
        fake_adapter=fake_adapter,
        issuer_signing_key=issuer_signing_key,
        service_principal=service_principal,
        agent_principal=agent_principal,
        now=now,
    )
    return pack.model_dump(mode="json")


def test_offline_verification_does_not_prove_the_pack_reflects_a_real_deployment(
    issuer_signing_key,
):
    """Documented limitation, not a bug: an adversary who controls key
    generation can produce a wholly self-consistent, self-signed pack that
    passes offline verification -- offline verification proves internal
    consistency of the artifact, not that any particular *organization*
    actually issued it. Recipients who need that must cross-check
    ``key_id`` against a separately, independently obtained trusted
    keyring -- see docs/portable-evidence.md."""
    from datetime import datetime, timezone

    from karmasakshi.audit.journal import AuditJournal
    from karmasakshi.crypto.keyring import Keyring
    from karmasakshi.domain.common import AdapterIdentity, MonetaryAmount, Principal
    from karmasakshi.domain.enums import (
        BlastRadiusClassification,
        PrincipalType,
        ReversibilityClassification,
        RiskClassification,
    )
    from karmasakshi.domain.manifest import EffectManifest
    from karmasakshi.protocol.sealing import seal_manifest

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    forger_key = issuer_signing_key
    manifest = EffectManifest(
        manifest_id="forged-1",
        effect_type="payment.transfer",
        actor=Principal(principal_id="a1", principal_type=PrincipalType.AGENT),
        principal=Principal(principal_id="p1", principal_type=PrincipalType.HUMAN),
        adapter=AdapterIdentity(adapter_id="payment.simulator", adapter_version="1.0.0"),
        target_resource="payment:victim",
        parameters={"amount": 999999},
        risk=RiskClassification.HIGH,
        reversibility=ReversibilityClassification.COMPENSATABLE,
        blast_radius=BlastRadiusClassification.SINGLE_RESOURCE,
        estimated_cost=MonetaryAmount(currency="INR", minor_units=999999),
        idempotency_key="idem-forged-1",
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        nonce="nonce-forged-1",
    )
    sealed = seal_manifest(manifest, forger_key)
    keyring = Keyring([forger_key.verification_key()])
    passport = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=AuditJournal(),
        lifecycle_state="sealed",
    )
    pack = build_evidence_pack(
        passport=passport,
        sealed_manifest=sealed,
        audit=AuditJournal(),
        keyring=keyring,
    )
    result = verify_evidence_pack(pack)
    assert result.all_verified is True  # internally consistent, but never authorized/committed
    assert passport.grant_id is None
    assert passport.commit_attempted is False
