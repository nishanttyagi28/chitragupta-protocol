"""Property tests for Decision Envelope substitution and hashing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from karmasakshi.crypto import generate_signing_key
from karmasakshi.domain.common import AdapterIdentity, Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.envelope import (
    assert_envelope_narrower_or_equal,
    build_decision_envelope,
    enum_of,
    exact,
    integer_range,
    substitute_parameters,
)
from karmasakshi.errors import DecisionEnvelopeConstraintError, DecisionEnvelopeSubstitutionError

_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_ISSUER = Principal(principal_id="user-1", principal_type=PrincipalType.HUMAN)
_KEY = generate_signing_key("dev-issuer-1")
_ADAPTER = AdapterIdentity(adapter_id="payment.simulator", adapter_version="1.0.0")


def _envelope(*, constraints, envelope_id="e", nonce="n", ttl_hours=1):
    return build_decision_envelope(
        envelope_id=envelope_id,
        effect_type="payment.transfer",
        adapter=_ADAPTER,
        target_resources=("r1",),
        parameter_constraints=constraints,
        issuer=_ISSUER,
        not_before=_NOW,
        expires_at=_NOW + timedelta(hours=ttl_hours),
        signing_key_id=_KEY.key_id,
        created_at=_NOW,
        nonce=nonce,
    )


@given(
    values=st.lists(
        st.one_of(
            st.integers(min_value=0, max_value=10_000),
            st.text(
                alphabet="abcdefghijklmnopqrstuvwxyz",
                min_size=1,
                max_size=8,
            ),
        ),
        min_size=1,
        max_size=8,
        unique=True,
    ),
    choice_index=st.integers(min_value=0, max_value=7),
)
@settings(max_examples=100)
def test_enum_substitution_is_order_independent(values, choice_index):
    choice = values[choice_index % len(values)]
    envelope_a = _envelope(constraints={"field": enum_of(*values)}, envelope_id="ea", nonce="na")
    envelope_b = _envelope(
        constraints={"field": enum_of(*reversed(values))}, envelope_id="ea", nonce="na"
    )
    assert envelope_a.canonical_hash() == envelope_b.canonical_hash()
    assert substitute_parameters(envelope_a, {"field": choice}) == substitute_parameters(
        envelope_b, {"field": choice}
    )


@given(
    lo=st.integers(min_value=0, max_value=50),
    hi=st.integers(min_value=50, max_value=100),
    value=st.integers(min_value=0, max_value=100),
)
@settings(max_examples=150)
def test_integer_range_substitution_matches_accepts(lo, hi, value):
    envelope = _envelope(constraints={"n": integer_range(min_int=lo, max_int=hi)})
    if lo <= value <= hi:
        assert substitute_parameters(envelope, {"n": value}) == {"n": value}
    else:
        try:
            substitute_parameters(envelope, {"n": value})
            raise AssertionError("expected substitution to fail")
        except DecisionEnvelopeSubstitutionError:
            pass


@given(
    child_max=st.integers(min_value=1, max_value=40),
    parent_max=st.integers(min_value=1, max_value=40),
)
@settings(max_examples=100)
def test_narrowing_is_monotonic_on_integer_ceiling(child_max, parent_max):
    parent = _envelope(
        constraints={"n": integer_range(min_int=0, max_int=parent_max)},
        envelope_id="parent",
        nonce="p",
    )
    child = _envelope(
        constraints={"n": integer_range(min_int=0, max_int=child_max)},
        envelope_id="child",
        nonce="c",
    )
    if child_max <= parent_max:
        assert_envelope_narrower_or_equal(child, parent)
    else:
        try:
            assert_envelope_narrower_or_equal(child, parent)
            raise AssertionError("expected widening to fail")
        except DecisionEnvelopeConstraintError:
            pass


@given(label=st.sampled_from(["a", "b", "c"]))
@settings(max_examples=30)
def test_exact_fill_needs_no_choice(label):
    envelope = _envelope(constraints={"x": exact(label)})
    assert substitute_parameters(envelope, {}) == {"x": label}
