from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from karmasakshi.errors import ManifestTamperedError, SchemaVersionError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.passports import (
    PASSPORT_FORMAT_V2,
    ActionPassportV2,
    OutcomeStatus,
    build_passport,
    build_passport_v2,
    derive_outcome_status,
    render_passport_v2_html,
    render_passport_v2_markdown,
    upgrade_passport_v1_to_v2,
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
    manifest = manifest_factory(manifest_id="passport-v2-1")
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


def test_passport_v2_upgrade_verified_match(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    v1 = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    v2 = upgrade_passport_v1_to_v2(v1, tenant_id="tenant-a")
    assert v2.passport_format == PASSPORT_FORMAT_V2
    assert v2.schema_version == "2.0"
    assert v2.outcome_status == OutcomeStatus.VERIFIED_MATCH
    assert v2.tenant_id == "tenant-a"
    assert v2.passport_hash.startswith("sha256:")
    v2.verify_passport_hash()


def test_build_passport_v2_matches_upgrade(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    mid = sealed.manifest.manifest_id
    direct = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(mid).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
        tenant_id="t1",
    )
    via = upgrade_passport_v1_to_v2(
        build_passport(
            sealed=sealed,
            keyring=keyring,
            audit=engine.context.audit,
            lifecycle_state=engine.get_lifecycle_state(mid).value,
            grant=grant,
            grant_store=engine.context.grant_store,
            commit_result=commit_result,
            outcome_proof=outcome_proof,
        ),
        tenant_id="t1",
    )
    assert direct.passport_hash == via.passport_hash
    assert direct.outcome_status == via.outcome_status


def test_passport_v2_hash_tamper_detected(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    v2 = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    tampered = v2.model_copy(update={"passport_hash": "sha256:" + ("a" * 64)})
    with pytest.raises(ManifestTamperedError):
        tampered.verify_passport_hash()


def test_passport_v2_rejects_wrong_schema_version(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    v2 = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    data = v2.model_dump(mode="json")
    data["schema_version"] = "1.0"
    with pytest.raises(SchemaVersionError):
        ActionPassportV2.model_validate(data)


def test_derive_outcome_status_revoked(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    engine.context.grant_store.revoke(grant.grant_id)
    v1 = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state="revoked",
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    assert derive_outcome_status(v1) == OutcomeStatus.REVOKED


def test_derive_outcome_status_mismatch(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    mismatched = replace(outcome_proof, matched_expected=False)
    v1 = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=mismatched,
    )
    assert derive_outcome_status(v1) == OutcomeStatus.VERIFIED_MISMATCH


def test_derive_outcome_status_authorized_not_committed(
    engine_factory,
    manifest_factory,
    fake_adapter,
    keyring,
    issuer_signing_key,
    now,
    service_principal,
    agent_principal,
):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="passport-v2-auth-only")
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
    v1 = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
    )
    assert derive_outcome_status(v1) == OutcomeStatus.AUTHORIZED_NOT_COMMITTED


def test_passport_v2_render(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    v2 = build_passport_v2(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    md = render_passport_v2_markdown(v2)
    assert "Action Passport V2" in md
    assert "Outcome status" in md
    assert v2.passport_hash in md
    html = render_passport_v2_html(v2)
    assert "karmasakshi-action-passport-v2" in html


def test_derive_outcome_status_failed_ambiguous_compensation(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run

    # RA-004: a matched independent observation must override a stale
    # terminal "failed" lifecycle label -- this is exactly the
    # ambiguous-recovery reconciliation fix (previously this asserted
    # OutcomeStatus.FAILED here, which is the bug the release audit found).
    failed_but_verified = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state="failed",
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    assert derive_outcome_status(failed_but_verified) == OutcomeStatus.VERIFIED_MATCH

    # With no independent evidence at all, a terminal "failed" lifecycle
    # state is still honestly reported as FAILED.
    failed_no_evidence = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state="failed",
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
    )
    assert derive_outcome_status(failed_no_evidence) == OutcomeStatus.FAILED

    from dataclasses import replace

    from karmasakshi.adapters.base import CompensationResult

    ambiguous_commit = replace(commit_result, detail="provider returned ambiguous timeout")
    amb = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state="committed",
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=ambiguous_commit,
    )
    assert derive_outcome_status(amb) == OutcomeStatus.AMBIGUOUS

    attempted = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state="compensated",
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
        compensation_result=CompensationResult(attempted=True, succeeded=False, reason="partial"),
    )
    assert derive_outcome_status(attempted) == OutcomeStatus.COMPENSATION_ATTEMPTED

    verified = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state="compensated",
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
        compensation_result=CompensationResult(attempted=True, succeeded=True, reason="ok"),
        compensation_passport_status="verified",
    )
    assert derive_outcome_status(verified) == OutcomeStatus.COMPENSATION_VERIFIED


def test_render_passport_v2_rejects_v1(full_run, keyring):
    engine, sealed, grant, commit_result, outcome_proof = full_run
    v1 = build_passport(
        sealed=sealed,
        keyring=keyring,
        audit=engine.context.audit,
        lifecycle_state=engine.get_lifecycle_state(sealed.manifest.manifest_id).value,
        grant=grant,
        grant_store=engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
    )
    with pytest.raises(TypeError):
        render_passport_v2_markdown(v1)  # type: ignore[arg-type]
