"""Adversarial tests for saga orchestration."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.causal import build_causal_graph, sign_causal_link
from karmasakshi.errors import SagaAmbiguousStepError, SagaGraphMismatchError
from karmasakshi.grants.model import ScopeConstraints


def test_swapped_graph_at_commit_is_rejected(
    engine_factory,
    manifest_factory,
    fake_adapter,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    m1 = engine.prepare(fake_adapter, manifest_factory(idempotency_key="a1", nonce="na"), None)
    m2 = engine.prepare(
        fake_adapter,
        manifest_factory(
            idempotency_key="a2",
            nonce="nb",
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
    other = build_causal_graph(node_manifest_hashes=(s1.seal.manifest_hash,), links=())
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
    with pytest.raises(SagaGraphMismatchError):
        engine.commit_saga_step(run.run_id, s1, grant, fake_adapter, None, causal_graph=other)


def test_blind_retry_of_ambiguous_step_blocked(
    engine_factory,
    manifest_factory,
    fake_adapter,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    m1 = engine.prepare(fake_adapter, manifest_factory(idempotency_key="amb1", nonce="namb"), None)
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
            run.run_id,
            s1,
            grant,
            fake_adapter,
            None,
            causal_graph=graph,
            ambiguous=True,
        )
    with pytest.raises(SagaAmbiguousStepError):
        engine.commit_saga_step(run.run_id, s1, grant, fake_adapter, None, causal_graph=graph)
