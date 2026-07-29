"""Unit tests for saga ordering, plan identity, and fail-closed transitions."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.causal import build_causal_graph, sign_causal_link
from karmasakshi.errors import (
    SagaAmbiguousStepError,
    SagaIllegalTransitionError,
)
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.saga import (
    SagaRunStatus,
    SagaStepStatus,
    assert_can_commit_step,
    build_saga_plan,
    mark_step_ambiguous,
    mark_step_authorized,
    mark_step_verified,
    start_compensation,
    topo_manifest_hashes,
)


def _two_node_graph(issuer_signing_key, keyring, now, hashes):
    a, b = hashes
    link = sign_causal_link(
        parent_manifest_hash=a,
        child_manifest_hash=b,
        relation="causes",
        signing_key=issuer_signing_key,
        created_at=now,
    )
    graph = build_causal_graph(node_manifest_hashes=(b, a), links=(link,))
    graph.verify(keyring)
    return graph


def test_topo_order_deterministic_and_parent_before_child(issuer_signing_key, keyring, now):
    a = "sha256:" + "a" * 64
    b = "sha256:" + "b" * 64
    graph = _two_node_graph(issuer_signing_key, keyring, now, (a, b))
    assert topo_manifest_hashes(graph) == (a, b)
    plan = build_saga_plan(graph, saga_id="s1", nonce="n1", created_at=now)
    again = build_saga_plan(graph, saga_id="s1", nonce="n1", created_at=now)
    assert plan.canonical_hash() == again.canonical_hash()
    assert plan.step_manifest_hashes == (a, b)


def test_ambiguous_step_blocks_recommit(issuer_signing_key, keyring, now, engine_factory):
    a = "sha256:" + "1" * 64
    b = "sha256:" + "2" * 64
    graph = _two_node_graph(issuer_signing_key, keyring, now, (a, b))
    engine = engine_factory()
    run = engine.begin_saga(graph, saga_id="s-amb")
    run = mark_step_authorized(run, a, grant_id="g1")
    run = mark_step_ambiguous(run, a, detail="timeout")
    assert run.status == SagaRunStatus.AWAITING_RECOVERY
    with pytest.raises(SagaAmbiguousStepError):
        assert_can_commit_step(run, a)


def test_compensation_starts_reverse_of_verified_only(
    issuer_signing_key, keyring, now, engine_factory
):
    a = "sha256:" + "3" * 64
    b = "sha256:" + "4" * 64
    graph = _two_node_graph(issuer_signing_key, keyring, now, (a, b))
    engine = engine_factory()
    run = engine.begin_saga(graph)
    run = mark_step_authorized(run, a, grant_id="g1")
    from karmasakshi.saga import mark_step_committed

    run = mark_step_committed(run, a, success=True, provider_reference="r1")
    run = mark_step_verified(run, a)
    assert run.cursor == 1
    run = start_compensation(run)
    assert run.status == SagaRunStatus.COMPENSATING
    assert run.compensation_cursor == 0


def test_engine_begin_and_wrong_step_rejected(
    engine_factory,
    manifest_factory,
    fake_adapter,
    human_principal,
    agent_principal,
    issuer_signing_key,
    keyring,
    now,
):
    engine = engine_factory()
    m1 = engine.prepare(fake_adapter, manifest_factory(idempotency_key="s1", nonce="n1"), None)
    m2 = engine.prepare(
        fake_adapter,
        manifest_factory(
            idempotency_key="s2",
            nonce="n2",
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
        node_manifest_hashes=(s1.seal.manifest_hash, s2.seal.manifest_hash),
        links=(link,),
    )
    run = engine.begin_saga(graph)
    assert run.status == SagaRunStatus.RUNNING

    with pytest.raises(SagaIllegalTransitionError):
        engine.authorize_saga_step(
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
    result = engine.commit_saga_step(run.run_id, s1, grant, fake_adapter, None, causal_graph=graph)
    assert result.success
    proof = engine.verify_saga_step(run.run_id, s1, result, fake_adapter, None)
    assert proof.matched_expected
    updated = engine.get_saga(run.run_id)
    assert updated.steps[0].status == SagaStepStatus.VERIFIED
    assert updated.cursor == 1
