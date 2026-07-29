"""Unit tests for constrained Decision Envelopes (extreme-v2 Phase 6)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from karmasakshi.causal import build_causal_graph, sign_causal_link
from karmasakshi.domain.common import MonetaryAmount
from karmasakshi.envelope import (
    assert_envelope_narrower_or_equal,
    assert_manifest_fits_envelope,
    assert_manifest_in_plan,
    build_decision_envelope,
    enum_of,
    exact,
    integer_range,
    monetary_range,
    seal_decision_envelope,
    substitute_parameters,
    verify_decision_envelope,
)
from karmasakshi.envelope.constraints import assert_constraint_narrower_or_equal
from karmasakshi.errors import (
    AtomicPlanError,
    DecisionEnvelopeConstraintError,
    DecisionEnvelopeExpiredError,
    DecisionEnvelopeIssuerNotAuthorizedError,
    DecisionEnvelopeSubstitutionError,
    IncomparableConstraintError,
    InvalidSignatureError,
)
from karmasakshi.grants.issuer import issue_grant
from karmasakshi.grants.model import ScopeConstraints


def _envelope(
    issuer,
    key,
    now,
    adapter,
    *,
    constraints=None,
    targets=("payment:beneficiary/X",),
    effect_type="payment.transfer",
    max_cost=None,
    graph_hash=None,
    ttl=3600,
):
    return build_decision_envelope(
        envelope_id="env-1",
        effect_type=effect_type,
        adapter=adapter,
        target_resources=targets,
        parameter_constraints=constraints
        or {
            "amount": monetary_range(currency="INR", min_minor_units=1, max_minor_units=150_000),
            "currency": enum_of("INR"),
        },
        issuer=issuer,
        not_before=now,
        expires_at=now + timedelta(seconds=ttl),
        signing_key_id=key.key_id,
        created_at=now,
        max_estimated_cost=max_cost,
        causal_graph_hash=graph_hash,
        nonce="n1",
    )


def test_constraint_accepts_and_rejects():
    assert exact("a").accepts("a") is None
    with pytest.raises(DecisionEnvelopeConstraintError):
        exact("a").accepts("b")
    enum_of("x", "y").accepts("x")
    with pytest.raises(DecisionEnvelopeConstraintError):
        enum_of("x", "y").accepts("z")
    integer_range(min_int=1, max_int=10).accepts(5)
    with pytest.raises(DecisionEnvelopeConstraintError):
        integer_range(min_int=1, max_int=10).accepts(11)
    with pytest.raises(DecisionEnvelopeConstraintError):
        integer_range(min_int=1, max_int=10).accepts("5")
    monetary_range(currency="INR", min_minor_units=0, max_minor_units=100).accepts(50)
    with pytest.raises(DecisionEnvelopeConstraintError):
        monetary_range(currency="INR", max_minor_units=100).accepts(101)


def test_enum_values_are_sorted_deterministically():
    a = enum_of("b", "a", 2, 1)
    b = enum_of(1, "a", 2, "b")
    assert a.allowed_values == b.allowed_values
    assert a.model_dump() == b.model_dump()


def test_agent_cannot_issue_decision_envelope(
    agent_principal, issuer_signing_key, now, adapter_identity
):
    with pytest.raises(DecisionEnvelopeIssuerNotAuthorizedError):
        _envelope(agent_principal, issuer_signing_key, now, adapter_identity)


def test_seal_verify_round_trip(
    human_principal, issuer_signing_key, keyring, now, adapter_identity
):
    unsigned = _envelope(human_principal, issuer_signing_key, now, adapter_identity)
    sealed = seal_decision_envelope(unsigned, issuer_signing_key)
    verify_decision_envelope(sealed, keyring, now=now)
    assert sealed.canonical_hash() == unsigned.canonical_hash()


def test_tampered_envelope_fails_signature(
    human_principal, issuer_signing_key, keyring, now, adapter_identity
):
    sealed = seal_decision_envelope(
        _envelope(human_principal, issuer_signing_key, now, adapter_identity),
        issuer_signing_key,
    )
    tampered = sealed.model_copy(update={"effect_type": "payment.refund"})
    with pytest.raises(InvalidSignatureError):
        verify_decision_envelope(tampered, keyring, now=now)


def test_expired_envelope_fails_closed(
    human_principal, issuer_signing_key, keyring, now, adapter_identity
):
    sealed = seal_decision_envelope(
        _envelope(human_principal, issuer_signing_key, now, adapter_identity, ttl=60),
        issuer_signing_key,
    )
    with pytest.raises(DecisionEnvelopeExpiredError):
        verify_decision_envelope(sealed, keyring, now=now + timedelta(seconds=61))


def test_manifest_fit_and_unknown_parameter_rejection(
    human_principal, issuer_signing_key, now, adapter_identity, manifest_factory
):
    envelope = seal_decision_envelope(
        _envelope(human_principal, issuer_signing_key, now, adapter_identity),
        issuer_signing_key,
    )
    good = manifest_factory(parameters={"amount": 1500, "currency": "INR"})
    assert_manifest_fits_envelope(good, envelope)

    bad_amount = manifest_factory(parameters={"amount": 200_000, "currency": "INR"})
    with pytest.raises(DecisionEnvelopeConstraintError, match="amount"):
        assert_manifest_fits_envelope(bad_amount, envelope)

    extra = manifest_factory(parameters={"amount": 1500, "currency": "INR", "memo": "extra"})
    with pytest.raises(DecisionEnvelopeConstraintError, match="outside envelope"):
        assert_manifest_fits_envelope(extra, envelope)


def test_deterministic_substitution(human_principal, issuer_signing_key, now, adapter_identity):
    envelope = _envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={
            "recipient": exact("customer-priya"),
            "amount": monetary_range(currency="INR", min_minor_units=1, max_minor_units=150_000),
            "currency": enum_of("INR", "USD"),
        },
    )
    resolved = substitute_parameters(envelope, {"amount": 1500, "currency": "INR"})
    assert list(resolved.keys()) == ["amount", "currency", "recipient"]
    assert resolved == {
        "amount": 1500,
        "currency": "INR",
        "recipient": "customer-priya",
    }
    again = substitute_parameters(envelope, {"currency": "INR", "amount": 1500})
    assert again == resolved


def test_substitution_rejects_exact_conflict_and_missing_choice(
    human_principal, issuer_signing_key, now, adapter_identity
):
    envelope = _envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={
            "recipient": exact("customer-priya"),
            "amount": monetary_range(currency="INR", max_minor_units=150_000),
        },
    )
    with pytest.raises(DecisionEnvelopeSubstitutionError, match="conflicts"):
        substitute_parameters(envelope, {"amount": 1500, "recipient": "someone-else"})
    with pytest.raises(DecisionEnvelopeSubstitutionError, match="requires an explicit"):
        substitute_parameters(envelope, {})


def test_envelope_narrowing_rejects_widening(
    human_principal, issuer_signing_key, now, adapter_identity
):
    parent = _envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={
            "amount": monetary_range(currency="INR", min_minor_units=0, max_minor_units=100_000),
            "recipient": enum_of("a", "b"),
        },
        targets=("r1", "r2"),
    )
    child_ok = _envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={
            "amount": monetary_range(currency="INR", min_minor_units=10, max_minor_units=50_000),
            "recipient": exact("a"),
        },
        targets=("r1",),
        ttl=1800,
    )
    assert_envelope_narrower_or_equal(child_ok, parent)

    child_wide_amount = _envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={
            "amount": monetary_range(currency="INR", min_minor_units=0, max_minor_units=200_000),
            "recipient": exact("a"),
        },
        targets=("r1",),
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="max_amount"):
        assert_envelope_narrower_or_equal(child_wide_amount, parent)

    child_extra_target = _envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={
            "amount": monetary_range(currency="INR", min_minor_units=0, max_minor_units=50_000),
            "recipient": exact("a"),
        },
        targets=("r1", "r3"),
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="target_resources"):
        assert_envelope_narrower_or_equal(child_extra_target, parent)


def test_constraint_narrowing_incomparable_kinds_fail_closed():
    with pytest.raises(IncomparableConstraintError):
        assert_constraint_narrower_or_equal(
            integer_range(min_int=1, max_int=5),
            enum_of("a", "b"),
            name="x",
        )


def test_grant_rejects_both_envelope_and_graph_hashes(
    human_principal, agent_principal, issuer_signing_key, now
):
    digest = "sha256:" + "a" * 64
    with pytest.raises(ValidationError, match="cannot bind to both"):
        issue_grant(
            grant_id="g1",
            issuer=human_principal,
            subject=agent_principal,
            audience=("payment.simulator",),
            allowed_effect_types=("payment.transfer",),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(seconds=60),
            nonce="n",
            signing_key=issuer_signing_key,
            manifest_hash=digest,
            decision_envelope_hash=digest,
            causal_graph_hash="sha256:" + "b" * 64,
        )


def test_atomic_plan_membership(issuer_signing_key, keyring, now, manifest_factory):
    m1 = manifest_factory(idempotency_key="p1", nonce="n-p1")
    m2 = manifest_factory(
        idempotency_key="p2",
        nonce="n-p2",
        manifest_id="22222222-2222-4222-8222-222222222222",
    )
    h1, h2 = m1.canonical_hash(), m2.canonical_hash()
    link = sign_causal_link(
        parent_manifest_hash=h1,
        child_manifest_hash=h2,
        relation="causes",
        signing_key=issuer_signing_key,
        created_at=now,
    )
    graph = build_causal_graph(node_manifest_hashes=(h1, h2), links=(link,))
    assert_manifest_in_plan(h2, graph, keyring=keyring)
    with pytest.raises(AtomicPlanError, match="not a node"):
        assert_manifest_in_plan("sha256:" + "c" * 64, graph, keyring=keyring)


def test_hash_stable_across_constraint_dict_order(
    human_principal, issuer_signing_key, now, adapter_identity
):
    a = _envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={"b": exact(1), "a": exact(2)},
    )
    b = _envelope(
        human_principal,
        issuer_signing_key,
        now,
        adapter_identity,
        constraints={"a": exact(2), "b": exact(1)},
    )
    assert a.canonical_hash() == b.canonical_hash()


def test_max_estimated_cost_enforced(
    human_principal, issuer_signing_key, now, adapter_identity, manifest_factory
):
    envelope = seal_decision_envelope(
        _envelope(
            human_principal,
            issuer_signing_key,
            now,
            adapter_identity,
            max_cost=MonetaryAmount(currency="INR", minor_units=10_000),
        ),
        issuer_signing_key,
    )
    over = manifest_factory(
        parameters={"amount": 1500, "currency": "INR"},
        estimated_cost=MonetaryAmount(currency="INR", minor_units=50_000),
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="estimated_cost"):
        assert_manifest_fits_envelope(over, envelope)
