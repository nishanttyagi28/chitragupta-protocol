from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from chitragupta.delegation import assert_scope_narrower_or_equal
from chitragupta.domain.common import MonetaryAmount
from chitragupta.errors import ConstraintWideningError, IncomparableConstraintError
from chitragupta.grants.model import ScopeConstraints

_recipient_universe = ["merchant-A", "merchant-B", "merchant-C", "merchant-D", "merchant-E"]
_recipient_sets = st.frozensets(st.sampled_from(_recipient_universe), min_size=1)


@given(_recipient_sets, _recipient_sets)
@settings(max_examples=200, deadline=None)
def test_subset_recipients_always_accepted_superset_never_widening(parent_set, child_set):
    parent = ScopeConstraints(recipients=tuple(sorted(parent_set)))
    child = ScopeConstraints(recipients=tuple(sorted(child_set)))
    is_subset = child_set.issubset(parent_set)
    if is_subset:
        assert_scope_narrower_or_equal(child, parent)  # must not raise
    else:
        try:
            assert_scope_narrower_or_equal(child, parent)
            raised = False
        except ConstraintWideningError:
            raised = True
        assert raised


@given(
    st.integers(min_value=0, max_value=10_000_000),
    st.integers(min_value=0, max_value=10_000_000),
)
@settings(max_examples=200, deadline=None)
def test_amount_monotonicity_same_currency(parent_amount, child_amount):
    parent = ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=parent_amount))
    child = ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=child_amount))
    if child_amount <= parent_amount:
        assert_scope_narrower_or_equal(child, parent)
    else:
        try:
            assert_scope_narrower_or_equal(child, parent)
            raised = False
        except ConstraintWideningError:
            raised = True
        assert raised


@given(st.sampled_from(["INR", "USD", "EUR", "GBP"]), st.sampled_from(["INR", "USD", "EUR", "GBP"]))
@settings(max_examples=50, deadline=None)
def test_currency_mismatch_is_always_incomparable_never_silently_allowed(parent_ccy, child_ccy):
    parent = ScopeConstraints(max_amount=MonetaryAmount(currency=parent_ccy, minor_units=1000))
    child = ScopeConstraints(max_amount=MonetaryAmount(currency=child_ccy, minor_units=1))
    if parent_ccy == child_ccy:
        assert_scope_narrower_or_equal(child, parent)
    else:
        try:
            assert_scope_narrower_or_equal(child, parent)
            raised = None
        except IncomparableConstraintError:
            raised = "incomparable"
        except ConstraintWideningError:
            raised = "widening"
        assert raised is not None  # never silently accepted across currencies


@given(_recipient_sets)
@settings(max_examples=100, deadline=None)
def test_scope_is_always_narrower_or_equal_to_itself(recipient_set):
    scope = ScopeConstraints(recipients=tuple(sorted(recipient_set)))
    assert_scope_narrower_or_equal(scope, scope)  # reflexivity
