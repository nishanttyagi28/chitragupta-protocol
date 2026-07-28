from __future__ import annotations

import pytest

from karmasakshi.canonical import CanonicalizationError, canonical_hash, canonical_json_bytes


def test_key_order_does_not_affect_hash():
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert canonical_json_bytes(a) == canonical_json_bytes(b)
    assert canonical_hash(a) == canonical_hash(b)


def test_nested_key_order_does_not_affect_hash():
    a = {"outer": {"z": 1, "a": 2}, "top": 1}
    b = {"top": 1, "outer": {"a": 2, "z": 1}}
    assert canonical_hash(a) == canonical_hash(b)


def test_no_insignificant_whitespace():
    data = {"a": 1, "b": [1, 2, 3]}
    out = canonical_json_bytes(data)
    assert b" " not in out
    assert out == b'{"a":1,"b":[1,2,3]}'


def test_floats_are_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"amount": 1.5})


def test_hash_is_stable_sha256_prefixed():
    h = canonical_hash({"x": 1})
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_different_values_produce_different_hashes():
    assert canonical_hash({"a": 1}) != canonical_hash({"a": 2})


def test_type_distinction_bool_vs_int():
    # bool is a subclass of int in Python; canonical json must keep them distinct
    assert canonical_json_bytes({"a": True}) != canonical_json_bytes({"a": 1})


def test_unsupported_type_raises():
    class Weird:
        pass

    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"a": Weird()})


def test_list_order_matters():
    assert canonical_hash([1, 2, 3]) != canonical_hash([3, 2, 1])
