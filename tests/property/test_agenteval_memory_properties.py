from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from karmasakshi.integrations.agenteval import failure_signature_for

_ident = st.text(
    alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=32
)


@given(effect_type=_ident, adapter_id=_ident, failure_category=_ident, invariant=st.none() | _ident)
@settings(max_examples=100)
def test_signature_is_deterministic(effect_type, adapter_id, failure_category, invariant):
    a = failure_signature_for(
        effect_type=effect_type,
        adapter_id=adapter_id,
        failure_category=failure_category,
        invariant=invariant,
    )
    b = failure_signature_for(
        effect_type=effect_type,
        adapter_id=adapter_id,
        failure_category=failure_category,
        invariant=invariant,
    )
    assert a == b
    assert a.startswith("sha256:")


@given(
    effect_type=_ident,
    adapter_id=_ident,
    category_a=_ident,
    category_b=_ident,
)
@settings(max_examples=100)
def test_different_failure_categories_yield_different_signatures(
    effect_type, adapter_id, category_a, category_b
):
    if category_a == category_b:
        return
    sig_a = failure_signature_for(
        effect_type=effect_type, adapter_id=adapter_id, failure_category=category_a, invariant=None
    )
    sig_b = failure_signature_for(
        effect_type=effect_type, adapter_id=adapter_id, failure_category=category_b, invariant=None
    )
    assert sig_a != sig_b


@given(effect_type=_ident, adapter_id=_ident, failure_category=_ident)
@settings(max_examples=50)
def test_invariant_none_differs_from_any_explicit_invariant(
    effect_type, adapter_id, failure_category
):
    without = failure_signature_for(
        effect_type=effect_type,
        adapter_id=adapter_id,
        failure_category=failure_category,
        invariant=None,
    )
    with_invariant = failure_signature_for(
        effect_type=effect_type,
        adapter_id=adapter_id,
        failure_category=failure_category,
        invariant="#1",
    )
    assert without != with_invariant
