"""Engine + passport wiring for independent witness quorum."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.errors import WitnessQuorumNotMetError
from karmasakshi.passports.generator import build_passport
from karmasakshi.witness import WitnessPolicy, sign_witness_statement


def _seal(engine, adapter, manifest, signing_key):
    prepared = engine.prepare(adapter, manifest, context=None)
    return engine.seal(prepared, signing_key)


def test_engine_prove_with_witness_quorum(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    engine = engine_factory()
    sealed = _seal(engine, fake_adapter, manifest_factory(), issuer_signing_key)
    policy = WitnessPolicy(required_witnesses=1)
    digest = "after-state-xyz"
    stmt = sign_witness_statement(
        statement_id="ws-1",
        manifest_hash=sealed.seal.manifest_hash,
        witness_policy_hash=policy.policy_hash(),
        observed_after_state_digest=digest,
        matched_expected=True,
        witness=human_principal,
        signing_key=issuer_signing_key,
        expires_at=fixed_clock.now() + timedelta(hours=1),
        nonce="n1",
        clock=fixed_clock,
    )
    result = engine.prove_with_witness_quorum(
        sealed,
        statements=[stmt],
        policy=policy,
        expected_after_state_digest=digest,
        actor=agent_principal,
        subject=agent_principal,
    )
    assert result.satisfied
    events = [
        e
        for e in engine._ctx.audit.events_for_manifest(sealed.manifest.manifest_id)
        if e.event_type.startswith("witness.")
    ]
    assert any(e.event_type == "witness.quorum_asserted" for e in events)


def test_engine_prove_raises_without_quorum(
    engine_factory, manifest_factory, fake_adapter, issuer_signing_key, agent_principal
):
    engine = engine_factory()
    sealed = _seal(engine, fake_adapter, manifest_factory(), issuer_signing_key)
    policy = WitnessPolicy(required_witnesses=2)
    with pytest.raises(WitnessQuorumNotMetError):
        engine.prove_with_witness_quorum(
            sealed,
            statements=[],
            policy=policy,
            expected_after_state_digest="d",
            actor=agent_principal,
            subject=agent_principal,
        )


def test_passport_surfaces_witness_fields(
    engine_factory, manifest_factory, fake_adapter, issuer_signing_key, human_principal
):
    engine = engine_factory()
    sealed = _seal(engine, fake_adapter, manifest_factory(), issuer_signing_key)
    passport = build_passport(
        sealed=sealed,
        keyring=engine._ctx.keyring,
        audit=engine._ctx.audit,
        lifecycle_state="verified",
        witness_set_hash="sha256:" + "c" * 64,
        witness_policy_hash="sha256:" + "d" * 64,
        witness_quorum_satisfied=True,
        accepted_witness_ids=(human_principal.principal_id,),
    )
    assert passport.witness_quorum_satisfied is True
    assert passport.accepted_witness_ids == (human_principal.principal_id,)
    assert passport.witness_set_hash is not None
