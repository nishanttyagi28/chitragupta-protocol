"""Extra coverage for saga machine edges and engine compensation recording."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.causal import build_causal_graph, sign_causal_link
from karmasakshi.compensation import CompensationStatus
from karmasakshi.errors import SagaAmbiguousStepError, SagaIllegalTransitionError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.saga import (
    SagaRunStatus,
    SagaStepStatus,
    assert_can_recover_step,
    mark_compensation_result,
    mark_step_authorized,
    mark_step_committed,
    mark_step_failed,
    mark_step_verified,
    next_compensation_manifest_hash,
    start_compensation,
)


def test_mark_step_failed_starts_compensation_or_aborts(
    issuer_signing_key, keyring, now, engine_factory
):
    a = "sha256:" + "5" * 64
    graph = build_causal_graph(node_manifest_hashes=(a,), links=())
    engine = engine_factory()
    run = engine.begin_saga(graph)
    run = mark_step_authorized(run, a, grant_id="g")
    aborted = mark_step_failed(run, a, detail="fail before commit")
    # No committed steps yet → ABORTED
    assert aborted.status == SagaRunStatus.ABORTED

    run2 = engine.begin_saga(graph, saga_id="s2")
    run2 = mark_step_authorized(run2, a, grant_id="g2")
    run2 = mark_step_committed(run2, a, success=True, provider_reference="r")
    run2 = mark_step_verified(run2, a)
    # Force a synthetic second failure path via start_compensation
    compensating = start_compensation(run2)
    assert compensating.status == SagaRunStatus.COMPENSATING
    assert next_compensation_manifest_hash(compensating) == a
    finished = mark_compensation_result(
        compensating, a, CompensationStatus.REFUSED, detail="irreversible"
    )
    assert finished.status == SagaRunStatus.FAILED_PARTIAL
    assert finished.steps[0].status == SagaStepStatus.COMPENSATION_REFUSED


def test_recover_helpers_and_engine_record_compensation(
    engine_factory,
    manifest_factory,
    fake_adapter,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    m1 = engine.prepare(fake_adapter, manifest_factory(idempotency_key="c1", nonce="nc1"), None)
    m2 = engine.prepare(
        fake_adapter,
        manifest_factory(
            idempotency_key="c2",
            nonce="nc2",
            manifest_id="22222222-2222-4222-8222-222222222222",
        ),
        None,
    )
    s1 = engine.seal(m1, issuer_signing_key)
    s2 = engine.seal(m2, issuer_signing_key)
    link = sign_causal_link(
        parent_manifest_hash=s1.seal.manifest_hash,
        child_manifest_hash=s2.seal.manifest_hash,
        relation="causes",
        signing_key=issuer_signing_key,
        created_at=now,
    )
    graph = build_causal_graph(
        node_manifest_hashes=(s1.seal.manifest_hash, s2.seal.manifest_hash), links=(link,)
    )
    run = engine.begin_saga(graph)
    g1 = engine.authorize_saga_step(
        run.run_id,
        s1,
        graph,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(s1.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    r1 = engine.commit_saga_step(run.run_id, s1, g1, fake_adapter, None, causal_graph=graph)
    engine.verify_saga_step(run.run_id, s1, r1, fake_adapter, None)

    g2 = engine.authorize_saga_step(
        run.run_id,
        s2,
        graph,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(s2.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    r2 = engine.commit_saga_step(run.run_id, s2, g2, fake_adapter, None, causal_graph=graph)
    assert r2.success
    current = engine.get_saga(run.run_id)
    current = start_compensation(current)
    engine._saga_runs[run.run_id] = current
    assert current.status == SagaRunStatus.COMPENSATING
    assert next_compensation_manifest_hash(current) == s2.seal.manifest_hash

    updated = engine.record_saga_compensation(
        run.run_id, s2.seal.manifest_hash, CompensationStatus.ATTEMPTED
    )
    assert updated.compensation_cursor == 0
    updated = engine.record_saga_compensation(
        run.run_id, s1.seal.manifest_hash, CompensationStatus.VERIFIED
    )
    assert updated.status == SagaRunStatus.FAILED_PARTIAL

    with pytest.raises(SagaIllegalTransitionError):
        assert_can_recover_step(updated, s1.seal.manifest_hash)


def test_recover_saga_step_with_and_without_evidence(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    m1 = engine.prepare(fake_adapter, manifest_factory(idempotency_key="rec1", nonce="nr1"), None)
    s1 = engine.seal(m1, issuer_signing_key)
    graph = build_causal_graph(node_manifest_hashes=(s1.seal.manifest_hash,), links=())
    run = engine.begin_saga(graph)
    grant = engine.authorize_saga_step(
        run.run_id,
        s1,
        graph,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(s1.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    with pytest.raises(SagaAmbiguousStepError):
        engine.commit_saga_step(
            run.run_id, s1, grant, fake_adapter, None, causal_graph=graph, ambiguous=True
        )
    # No evidence → compensation/abort path
    fake_adapter_state.matched_expected = False
    proof = engine.recover_saga_step(run.run_id, s1, fake_adapter, None)
    assert proof.matched_expected is False
    assert engine.get_saga(run.run_id).status == SagaRunStatus.ABORTED


def test_recover_with_evidence_continues(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    m1 = engine.prepare(fake_adapter, manifest_factory(idempotency_key="rec2", nonce="nr2"), None)
    s1 = engine.seal(m1, issuer_signing_key)
    graph = build_causal_graph(node_manifest_hashes=(s1.seal.manifest_hash,), links=())
    run = engine.begin_saga(graph)
    grant = engine.authorize_saga_step(
        run.run_id,
        s1,
        graph,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(s1.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    with pytest.raises(SagaAmbiguousStepError):
        engine.commit_saga_step(
            run.run_id, s1, grant, fake_adapter, None, causal_graph=graph, ambiguous=True
        )
    fake_adapter_state.matched_expected = True
    fake_adapter_state.external_effects[s1.manifest.idempotency_key] = "recovered-ref"
    proof = engine.recover_saga_step(run.run_id, s1, fake_adapter, None)
    assert proof.matched_expected is True
    assert engine.get_saga(run.run_id).steps[0].status == SagaStepStatus.COMMITTED


def test_machine_guard_errors(issuer_signing_key, keyring, now, engine_factory):
    a = "sha256:" + "7" * 64
    b = "sha256:" + "8" * 64
    link = sign_causal_link(
        parent_manifest_hash=a,
        child_manifest_hash=b,
        relation="causes",
        signing_key=issuer_signing_key,
        created_at=now,
    )
    graph = build_causal_graph(node_manifest_hashes=(a, b), links=(link,))
    engine = engine_factory()
    run = engine.begin_saga(graph)
    with pytest.raises(SagaIllegalTransitionError):
        mark_step_authorized(run, b, grant_id="g")
    with pytest.raises(SagaIllegalTransitionError):
        mark_step_verified(run, a)
    with pytest.raises(SagaIllegalTransitionError):
        engine.get_saga("missing")
    with pytest.raises(SagaIllegalTransitionError):
        engine.record_saga_compensation(run.run_id, a, CompensationStatus.REFUSED)


def test_commit_saga_step_failure_starts_abort(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    m1 = engine.prepare(fake_adapter, manifest_factory(idempotency_key="fail1", nonce="nf1"), None)
    s1 = engine.seal(m1, issuer_signing_key)
    graph = build_causal_graph(node_manifest_hashes=(s1.seal.manifest_hash,), links=())
    run = engine.begin_saga(graph)
    grant = engine.authorize_saga_step(
        run.run_id,
        s1,
        graph,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(s1.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    fake_adapter_state.fail_commit = True
    result = engine.commit_saga_step(run.run_id, s1, grant, fake_adapter, None, causal_graph=graph)
    assert result.success is False
    assert engine.get_saga(run.run_id).status == SagaRunStatus.ABORTED


def test_adapter_crash_during_saga_commit(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    m1 = engine.prepare(fake_adapter, manifest_factory(idempotency_key="crash1", nonce="ncr"), None)
    s1 = engine.seal(m1, issuer_signing_key)
    graph = build_causal_graph(node_manifest_hashes=(s1.seal.manifest_hash,), links=())
    run = engine.begin_saga(graph)
    grant = engine.authorize_saga_step(
        run.run_id,
        s1,
        graph,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(s1.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    fake_adapter_state.raise_on_commit = True
    with pytest.raises(RuntimeError):
        engine.commit_saga_step(run.run_id, s1, grant, fake_adapter, None, causal_graph=graph)
    assert engine.get_saga(run.run_id).status == SagaRunStatus.ABORTED
