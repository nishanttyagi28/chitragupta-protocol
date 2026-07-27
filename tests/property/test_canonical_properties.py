from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from chitragupta.canonical import CanonicalizationError, canonical_hash, canonical_json_bytes

_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**15), max_value=10**15),
    st.text(max_size=50),
)


def _json_value(children):
    return st.one_of(
        _json_scalar,
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=20), children, max_size=5),
    )


_json_tree = st.recursive(_json_scalar, _json_value, max_leaves=20)


@given(_json_tree)
@settings(max_examples=200, deadline=None)
def test_canonical_hash_is_deterministic_across_runs(value):
    assert canonical_hash(value) == canonical_hash(value)


@given(st.dictionaries(st.text(max_size=20), _json_scalar, max_size=8))
@settings(max_examples=200, deadline=None)
def test_dict_key_order_never_affects_hash(d):
    shuffled = dict(reversed(list(d.items())))
    assert canonical_hash(d) == canonical_hash(shuffled)


@given(_json_tree)
@settings(max_examples=200, deadline=None)
def test_canonical_bytes_have_no_insignificant_whitespace(value):
    out = canonical_json_bytes(value)
    # No newline/tab, and no ", " or ": " (only compact separators are used).
    assert b"\n" not in out
    assert b"\t" not in out
    assert b", " not in out
    assert b": " not in out


@given(st.floats(allow_nan=False, allow_infinity=False))
@settings(max_examples=50, deadline=None)
def test_floats_are_always_rejected(f):
    try:
        canonical_json_bytes({"x": f})
        raised = False
    except CanonicalizationError:
        raised = True
    assert raised


@given(_json_tree, _json_tree)
@settings(max_examples=200, deadline=None)
def test_different_values_generally_produce_different_hashes(a, b):
    if canonical_json_bytes(a) != canonical_json_bytes(b):
        assert canonical_hash(a) != canonical_hash(b)
