"""Additional coverage for Decision Envelope edge paths (Phase 6)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from karmasakshi.domain.common import MonetaryAmount
from karmasakshi.envelope import (
    assert_constraint_narrower_or_equal,
    assert_envelope_narrower_or_equal,
    assert_manifest_fits_envelope,
    build_decision_envelope,
    enum_of,
    exact,
    integer_range,
    is_fully_exact,
    missing_substitution_keys,
    monetary_range,
    seal_decision_envelope,
    substitute_parameters,
    verify_decision_envelope,
)
from karmasakshi.envelope.constraints import ParameterConstraint
from karmasakshi.envelope.plan import plan_node_count, require_matching_plan_hash
from karmasakshi.envelope.sealing import assert_envelope_integrity
from karmasakshi.envelope.substitution import constraint_summary, default_exact_parameters
from karmasakshi.errors import (
    DecisionEnvelopeConstraintError,
    DecisionEnvelopeNotYetValidError,
    DecisionEnvelopeSubstitutionError,
    DecisionEnvelopeTamperedError,
    IncomparableConstraintError,
    InvalidSignatureError,
)


def test_constraint_construction_rejects_malformed_shapes():
    with pytest.raises(ValidationError):
        ParameterConstraint(kind="exact")  # missing exact_value
    with pytest.raises(ValidationError):
        ParameterConstraint(kind="enum", allowed_values=())
    with pytest.raises(ValidationError):
        ParameterConstraint(kind="enum", allowed_values=("a", "a"))
    with pytest.raises(ValidationError):
        ParameterConstraint(kind="integer_range")
    with pytest.raises(ValidationError):
        ParameterConstraint(kind="integer_range", min_int=5, max_int=1)
    with pytest.raises(ValidationError):
        ParameterConstraint(kind="monetary_range", currency="INR")
    with pytest.raises(ValidationError):
        monetary_range(currency="INR", min_minor_units=10, max_minor_units=1)
    with pytest.raises(ValidationError):
        ParameterConstraint(
            kind="exact",
            exact_value=1,
            allowed_values=("x",),
        )
    with pytest.raises(ValidationError):
        ParameterConstraint(kind="enum", allowed_values=("a",), min_int=1)
    with pytest.raises(ValidationError):
        ParameterConstraint(kind="integer_range", min_int=1, allowed_values=("a",))
    with pytest.raises(ValidationError):
        ParameterConstraint(
            kind="integer_range",
            min_int=1,
            exact_value=1,
        )
    with pytest.raises(ValidationError):
        ParameterConstraint(
            kind="monetary_range",
            currency="INR",
            min_amount=MonetaryAmount(currency="INR", minor_units=1),
            max_amount=MonetaryAmount(currency="USD", minor_units=2),
        )


def test_accepts_unknown_kind_and_bool_rejected_as_int():
    # bool is a subclass of int in Python; constraints must reject it.
    with pytest.raises(DecisionEnvelopeConstraintError):
        integer_range(min_int=0, max_int=10).accepts(True)  # type: ignore[arg-type]
    with pytest.raises(DecisionEnvelopeConstraintError):
        monetary_range(currency="INR", max_minor_units=100).accepts(True)  # type: ignore[arg-type]


def test_constraint_narrowing_exact_and_enum_paths():
    parent_enum = enum_of("a", "b", "c")
    assert_constraint_narrower_or_equal(exact("a"), parent_enum, name="x")
    with pytest.raises(DecisionEnvelopeConstraintError):
        assert_constraint_narrower_or_equal(exact("z"), parent_enum, name="x")
    with pytest.raises(DecisionEnvelopeConstraintError):
        assert_constraint_narrower_or_equal(enum_of("a", "b"), exact("a"), name="x")
    assert_constraint_narrower_or_equal(enum_of("a"), parent_enum, name="x")
    with pytest.raises(DecisionEnvelopeConstraintError):
        assert_constraint_narrower_or_equal(enum_of("a", "z"), parent_enum, name="x")
    parent_int = integer_range(min_int=0, max_int=10)
    assert_constraint_narrower_or_equal(enum_of(1, 2), parent_int, name="n")
    with pytest.raises(DecisionEnvelopeConstraintError):
        assert_constraint_narrower_or_equal(enum_of(1, 99), parent_int, name="n")
    parent_money = monetary_range(currency="INR", min_minor_units=0, max_minor_units=100)
    assert_constraint_narrower_or_equal(enum_of(50), parent_money, name="m")
    with pytest.raises(DecisionEnvelopeConstraintError):
        assert_constraint_narrower_or_equal(enum_of(200), parent_money, name="m")
    with pytest.raises(IncomparableConstraintError):
        assert_constraint_narrower_or_equal(
            monetary_range(currency="USD", max_minor_units=10),
            parent_money,
            name="m",
        )
    with pytest.raises(DecisionEnvelopeConstraintError):
        assert_constraint_narrower_or_equal(
            integer_range(min_int=None, max_int=5),  # type: ignore[arg-type]
            integer_range(min_int=1, max_int=5),
            name="n",
        )


def test_envelope_validation_and_fit_edges(
    human_principal, issuer_signing_key, now, adapter_identity, manifest_factory
):
    with pytest.raises(ValidationError):
        build_decision_envelope(
            effect_type="payment.transfer",
            adapter=adapter_identity,
            target_resources=(),
            parameter_constraints={"a": exact(1)},
            issuer=human_principal,
            not_before=now,
            expires_at=now + timedelta(hours=1),
            signing_key_id=issuer_signing_key.key_id,
        )
    with pytest.raises(ValidationError):
        build_decision_envelope(
            effect_type="payment.transfer",
            adapter=adapter_identity,
            target_resources=("r1",),
            parameter_constraints={"a": exact(1)},
            issuer=human_principal,
            not_before=now,
            expires_at=now,  # not strictly after
            signing_key_id=issuer_signing_key.key_id,
        )
    with pytest.raises(ValidationError):
        build_decision_envelope(
            effect_type="payment.transfer",
            adapter=adapter_identity,
            target_resources=("r1",),
            parameter_constraints={"a": exact(1)},
            issuer=human_principal,
            not_before=now,
            expires_at=now + timedelta(hours=1),
            signing_key_id=issuer_signing_key.key_id,
            causal_graph_hash="not-a-hash",
        )

    envelope = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("payment:beneficiary/X",),
        parameter_constraints={"amount": exact(1500), "currency": exact("INR")},
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key_id=issuer_signing_key.key_id,
        max_estimated_cost=MonetaryAmount(currency="INR", minor_units=10_000),
        require_all_constrained_parameters=True,
        forbid_unknown_parameters=True,
    )
    wrong_type = manifest_factory(effect_type="other")
    with pytest.raises(DecisionEnvelopeConstraintError, match="effect_type"):
        assert_manifest_fits_envelope(wrong_type, envelope)
    wrong_target = manifest_factory(target_resource="other")
    with pytest.raises(DecisionEnvelopeConstraintError, match="target_resource"):
        assert_manifest_fits_envelope(wrong_target, envelope)
    missing = manifest_factory(parameters={"amount": 1500})
    with pytest.raises(DecisionEnvelopeConstraintError, match="missing required"):
        assert_manifest_fits_envelope(missing, envelope)
    no_cost = manifest_factory(parameters={"amount": 1500, "currency": "INR"}, estimated_cost=None)
    with pytest.raises(DecisionEnvelopeConstraintError, match="no estimated_cost"):
        assert_manifest_fits_envelope(no_cost, envelope)
    bad_currency_cost = manifest_factory(
        parameters={"amount": 1500, "currency": "INR"},
        estimated_cost=MonetaryAmount(currency="USD", minor_units=100),
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="currency"):
        assert_manifest_fits_envelope(bad_currency_cost, envelope)


def test_envelope_narrowing_policy_and_graph_and_window(
    human_principal, issuer_signing_key, now, adapter_identity
):
    parent = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"n": integer_range(min_int=0, max_int=10)},
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=2),
        signing_key_id=issuer_signing_key.key_id,
        max_estimated_cost=MonetaryAmount(currency="INR", minor_units=1000),
        causal_graph_hash="sha256:" + "a" * 64,
        require_all_constrained_parameters=True,
        forbid_unknown_parameters=True,
        envelope_id="parent",
        nonce="p",
    )
    with pytest.raises(IncomparableConstraintError):
        assert_envelope_narrower_or_equal(
            build_decision_envelope(
                effect_type="other",
                adapter=adapter_identity,
                target_resources=("r1",),
                parameter_constraints={"n": integer_range(min_int=0, max_int=5)},
                issuer=human_principal,
                not_before=now,
                expires_at=now + timedelta(hours=1),
                signing_key_id=issuer_signing_key.key_id,
                envelope_id="c",
                nonce="c",
            ),
            parent,
        )
    child_no_cost = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"n": integer_range(min_int=0, max_int=5)},
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key_id=issuer_signing_key.key_id,
        causal_graph_hash="sha256:" + "a" * 64,
        envelope_id="c2",
        nonce="c2",
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="max_estimated_cost"):
        assert_envelope_narrower_or_equal(child_no_cost, parent)
    child_wrong_graph = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"n": integer_range(min_int=0, max_int=5)},
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key_id=issuer_signing_key.key_id,
        max_estimated_cost=MonetaryAmount(currency="INR", minor_units=500),
        causal_graph_hash="sha256:" + "b" * 64,
        envelope_id="c3",
        nonce="c3",
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="causal_graph_hash"):
        assert_envelope_narrower_or_equal(child_wrong_graph, parent)
    parent_no_graph = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"n": integer_range(min_int=0, max_int=10)},
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=2),
        signing_key_id=issuer_signing_key.key_id,
        envelope_id="png",
        nonce="png",
    )
    child_adds_graph = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"n": integer_range(min_int=0, max_int=5)},
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key_id=issuer_signing_key.key_id,
        causal_graph_hash="sha256:" + "a" * 64,
        envelope_id="cag",
        nonce="cag",
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="introduces a graph"):
        assert_envelope_narrower_or_equal(child_adds_graph, parent_no_graph)
    child_relax_required = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"n": integer_range(min_int=0, max_int=5)},
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key_id=issuer_signing_key.key_id,
        max_estimated_cost=MonetaryAmount(currency="INR", minor_units=500),
        causal_graph_hash="sha256:" + "a" * 64,
        require_all_constrained_parameters=False,
        envelope_id="cr",
        nonce="cr",
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="require_all"):
        assert_envelope_narrower_or_equal(child_relax_required, parent)
    child_outlives = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"n": integer_range(min_int=0, max_int=5)},
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=3),
        signing_key_id=issuer_signing_key.key_id,
        max_estimated_cost=MonetaryAmount(currency="INR", minor_units=500),
        causal_graph_hash="sha256:" + "a" * 64,
        envelope_id="co",
        nonce="co",
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="expires_at"):
        assert_envelope_narrower_or_equal(child_outlives, parent)
    child_early = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"n": integer_range(min_int=0, max_int=5)},
        issuer=human_principal,
        not_before=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=1),
        signing_key_id=issuer_signing_key.key_id,
        max_estimated_cost=MonetaryAmount(currency="INR", minor_units=500),
        causal_graph_hash="sha256:" + "a" * 64,
        envelope_id="ce",
        nonce="ce",
    )
    with pytest.raises(DecisionEnvelopeConstraintError, match="not_before"):
        assert_envelope_narrower_or_equal(child_early, parent)


def test_sealing_edge_cases(
    human_principal, issuer_signing_key, other_signing_key, keyring, now, adapter_identity
):
    unsigned = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"x": exact(1)},
        issuer=human_principal,
        not_before=now + timedelta(hours=1),
        expires_at=now + timedelta(hours=2),
        signing_key_id=issuer_signing_key.key_id,
        created_at=now,
    )
    with pytest.raises(InvalidSignatureError, match="does not match"):
        seal_decision_envelope(
            unsigned.model_copy(update={"key_id": other_signing_key.key_id}),
            issuer_signing_key,
        )
    sealed = seal_decision_envelope(unsigned, issuer_signing_key)
    with pytest.raises(InvalidSignatureError, match="already signed"):
        seal_decision_envelope(sealed, issuer_signing_key)
    with pytest.raises(InvalidSignatureError, match="unsigned"):
        verify_decision_envelope(unsigned, keyring, now=now)
    with pytest.raises(DecisionEnvelopeNotYetValidError):
        verify_decision_envelope(sealed, keyring, now=now)
    assert_envelope_integrity(sealed, sealed.canonical_hash())
    with pytest.raises(DecisionEnvelopeTamperedError):
        assert_envelope_integrity(sealed, "sha256:" + "0" * 64)


def test_substitution_helpers(human_principal, issuer_signing_key, now, adapter_identity):
    envelope = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={
            "a": exact(1),
            "b": integer_range(min_int=0, max_int=5),
            "c": enum_of("x", "y"),
            "d": monetary_range(currency="INR", max_minor_units=100),
        },
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key_id=issuer_signing_key.key_id,
    )
    assert default_exact_parameters(envelope) == {"a": 1}
    assert missing_substitution_keys(envelope, {}) == ("b", "c", "d")
    assert is_fully_exact(envelope) is False
    exact_only = build_decision_envelope(
        effect_type="payment.transfer",
        adapter=adapter_identity,
        target_resources=("r1",),
        parameter_constraints={"a": exact(1)},
        issuer=human_principal,
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key_id=issuer_signing_key.key_id,
        envelope_id="eo",
        nonce="eo",
    )
    assert is_fully_exact(exact_only) is True
    assert constraint_summary(exact(1))["kind"] == "exact"
    assert constraint_summary(enum_of("a"))["kind"] == "enum"
    assert constraint_summary(integer_range(min_int=1, max_int=2))["kind"] == "integer_range"
    assert constraint_summary(monetary_range(currency="INR", max_minor_units=1))["kind"] == (
        "monetary_range"
    )
    with pytest.raises(DecisionEnvelopeSubstitutionError):
        substitute_parameters(envelope, {"b": 99, "c": "x", "d": 1})


def test_plan_helpers(issuer_signing_key, keyring, now, manifest_factory):
    from karmasakshi.causal import build_causal_graph
    from karmasakshi.errors import AtomicPlanError

    m = manifest_factory()
    h = m.canonical_hash()
    graph = build_causal_graph(node_manifest_hashes=(h,), links=())
    assert plan_node_count(graph) == 1
    require_matching_plan_hash(graph, graph.canonical_hash())
    with pytest.raises(AtomicPlanError):
        require_matching_plan_hash(graph, "sha256:" + "0" * 64)
