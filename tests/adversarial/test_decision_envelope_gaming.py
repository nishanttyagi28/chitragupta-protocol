"""Adversarial tests for Decision Envelope widening and plan binding."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.causal import build_causal_graph, sign_causal_link
from karmasakshi.envelope import (
    assert_envelope_narrower_or_equal,
    build_decision_envelope,
    enum_of,
    exact,
    monetary_range,
    seal_decision_envelope,
    substitute_parameters,
    verify_decision_envelope,
)
from karmasakshi.errors import (
    AtomicPlanError,
    DecisionEnvelopeConstraintError,
    DecisionEnvelopeSubstitutionError,
    InvalidSignatureError,
    UnknownKeyError,
)
from karmasakshi.grants.model import ScopeConstraints


def _prepare_and_seal(engine, adapter, manifest, signing_key):
    prepared = engine.prepare(adapter, manifest, context=None)
    return engine.seal(prepared, signing_key)


def _base_envelope(human_principal, key, now, adapter, **kwargs):
    return build_decision_envelope(
        envelope_id=kwargs.get("envelope_id", "env"),
        effect_type="payment.transfer",
        adapter=adapter,
        target_resources=kwargs.get("targets", ("payment:beneficiary/X",)),
        parameter_constraints=kwargs.get(
            "constraints",
            {
                "amount": monetary_range(
                    currency="INR", min_minor_units=0, max_minor_units=200_000
                ),
                "currency": exact("INR"),
            },
        ),
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key_id=key.key_id,
        created_at=now,
        nonce=kwargs.get("nonce", "n"),
        causal_graph_hash=kwargs.get("causal_graph_hash"),
        max_estimated_cost=kwargs.get("max_estimated_cost"),
        forbid_unknown_parameters=kwargs.get("forbid_unknown_parameters", True),
        require_all_constrained_parameters=kwargs.get("require_all_constrained_parameters", True),
    )


def test_stolen_signature_cannot_cover_widened_envelope(
    human_principal, issuer_signing_key, keyring, now, adapter_identity
):
    sealed = seal_decision_envelope(
        _base_envelope(human_principal, issuer_signing_key, now, adapter_identity),
        issuer_signing_key,
    )
    widened = _base_envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={
            "amount": monetary_range(currency="INR", min_minor_units=0, max_minor_units=9_999_999),
            "currency": exact("INR"),
        },
    )
    frankenstein = widened.model_copy(update={"signature": sealed.signature})
    with pytest.raises(InvalidSignatureError):
        verify_decision_envelope(frankenstein, keyring, now=now)


def test_unknown_signer_fails_closed(
    human_principal, other_signing_key, keyring, now, adapter_identity
):
    sealed = seal_decision_envelope(
        _base_envelope(human_principal, other_signing_key, now, adapter_identity),
        other_signing_key,
    )
    with pytest.raises(UnknownKeyError):
        verify_decision_envelope(sealed, keyring, now=now)


def test_child_cannot_drop_parent_constraint(
    human_principal, issuer_signing_key, now, adapter_identity
):
    parent = _base_envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={
            "amount": monetary_range(currency="INR", max_minor_units=100_000),
            "currency": exact("INR"),
            "recipient": enum_of("a", "b"),
        },
    )
    child = _base_envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={
            "amount": monetary_range(currency="INR", max_minor_units=50_000),
            "currency": exact("INR"),
        },
        envelope_id="child",
        nonce="c",
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="drops parent"):
        assert_envelope_narrower_or_equal(child, parent)


def test_child_cannot_relax_unknown_parameter_policy(
    human_principal, issuer_signing_key, now, adapter_identity
):
    parent = _base_envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        forbid_unknown_parameters=True,
    )
    child = _base_envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        forbid_unknown_parameters=False,
        envelope_id="child",
        nonce="c",
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="forbid_unknown"):
        assert_envelope_narrower_or_equal(child, parent)


def test_substitution_cannot_inject_unconstrained_key(
    human_principal, issuer_signing_key, now, adapter_identity
):
    envelope = _base_envelope(human_principal, issuer_signing_key, now, adapter_identity)
    with pytest.raises(DecisionEnvelopeSubstitutionError, match="unconstrained"):
        substitute_parameters(envelope, {"amount": 100, "evil": "x"})


def test_authorize_with_envelope_then_commit_rejects_missing_and_swapped(
    engine_factory,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
    adapter_identity,
    manifest_factory,
    fake_adapter,
):
    from karmasakshi.errors import DecisionEnvelopeMismatchError

    engine = engine_factory()
    sealed = _prepare_and_seal(engine, fake_adapter, manifest_factory(), issuer_signing_key)
    envelope = seal_decision_envelope(
        _base_envelope(human_principal, issuer_signing_key, now, adapter_identity),
        issuer_signing_key,
    )
    other = seal_decision_envelope(
        _base_envelope(
            human_principal,
            issuer_signing_key,
            now,
            adapter_identity,
            constraints={
                "amount": monetary_range(currency="INR", max_minor_units=50_000),
                "currency": exact("INR"),
            },
            envelope_id="other",
            nonce="other",
        ),
        issuer_signing_key,
    )
    grant = engine.authorize_with_envelope(
        sealed,
        envelope,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    assert grant.decision_envelope_hash == envelope.canonical_hash()
    assert grant.causal_graph_hash is None

    with pytest.raises(DecisionEnvelopeMismatchError, match="requires decision envelope"):
        engine.commit(sealed, grant, fake_adapter, context=None)

    with pytest.raises(DecisionEnvelopeMismatchError, match="different envelope"):
        engine.commit(sealed, grant, fake_adapter, context=None, decision_envelope=other)

    result = engine.commit(sealed, grant, fake_adapter, context=None, decision_envelope=envelope)
    assert result.success is True


def test_authorize_plan_rejects_non_member_and_commit_requires_graph(
    engine_factory,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
    manifest_factory,
    fake_adapter,
):
    engine = engine_factory()
    sealed_a = _prepare_and_seal(
        engine, fake_adapter, manifest_factory(idempotency_key="a", nonce="na"), issuer_signing_key
    )
    sealed_b = _prepare_and_seal(
        engine,
        fake_adapter,
        manifest_factory(
            idempotency_key="b",
            nonce="nb",
            manifest_id="22222222-2222-4222-8222-222222222222",
        ),
        issuer_signing_key,
    )
    outsider = _prepare_and_seal(
        engine,
        fake_adapter,
        manifest_factory(
            idempotency_key="c",
            nonce="nc",
            manifest_id="33333333-3333-4333-8333-333333333333",
        ),
        issuer_signing_key,
    )
    link = sign_causal_link(
        parent_manifest_hash=sealed_a.seal.manifest_hash,
        child_manifest_hash=sealed_b.seal.manifest_hash,
        relation="causes",
        signing_key=issuer_signing_key,
        created_at=now,
    )
    graph = build_causal_graph(
        node_manifest_hashes=(sealed_a.seal.manifest_hash, sealed_b.seal.manifest_hash),
        links=(link,),
    )
    with pytest.raises(AtomicPlanError, match="not a node"):
        engine.authorize_plan(
            outsider,
            graph,
            issuer=human_principal,
            subject=agent_principal,
            audience=(fake_adapter.adapter_id,),
            allowed_effect_types=(outsider.manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            signing_key=issuer_signing_key,
        )

    grant = engine.authorize_plan(
        sealed_b,
        graph,
        issuer=human_principal,
        subject=agent_principal,
        audience=(fake_adapter.adapter_id,),
        allowed_effect_types=(sealed_b.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )
    assert grant.causal_graph_hash == graph.canonical_hash()
    assert grant.decision_envelope_hash is None

    with pytest.raises(AtomicPlanError, match="requires causal graph"):
        engine.commit(sealed_b, grant, fake_adapter, context=None)

    result = engine.commit(sealed_b, grant, fake_adapter, context=None, causal_graph=graph)
    assert result.success is True


def test_manifest_outside_envelope_blocks_authorize(
    engine_factory,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
    adapter_identity,
    manifest_factory,
    fake_adapter,
):
    engine = engine_factory()
    sealed = _prepare_and_seal(
        engine,
        fake_adapter,
        manifest_factory(parameters={"amount": 200_000, "currency": "INR"}),
        issuer_signing_key,
    )
    envelope = seal_decision_envelope(
        _base_envelope(
            human_principal,
            issuer_signing_key,
            now,
            adapter_identity,
            constraints={
                "amount": monetary_range(
                    currency="INR", min_minor_units=0, max_minor_units=100_000
                ),
                "currency": exact("INR"),
            },
        ),
        issuer_signing_key,
    )
    with pytest.raises(DecisionEnvelopeConstraintError):
        engine.authorize_with_envelope(
            sealed,
            envelope,
            issuer=human_principal,
            subject=agent_principal,
            audience=(adapter_identity.adapter_id,),
            allowed_effect_types=(sealed.manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            signing_key=issuer_signing_key,
        )
