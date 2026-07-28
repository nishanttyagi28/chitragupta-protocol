"""Cross-process canonicalization fixtures.

These hashes were computed once and hardcoded here. If canonicalization
ever changes in a way that breaks cross-process/cross-version agreement
(the entire point of the algorithm), these tests fail -- they are a
tripwire against silent algorithm drift, not just internal self-consistency
checks like test_canonical_properties.py.
"""

from __future__ import annotations

from karmasakshi.canonical import canonical_hash

_FIXTURES = [
    ({"a": 1, "b": 2}, "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"),
    (
        {"z": "last", "a": "first", "m": "middle"},
        "sha256:41d4c7df095932154cd6cb6671d5029329a9333061589cfc9191591e181b94d5",
    ),
    (
        {"nested": {"b": 2, "a": 1}, "top": True},
        "sha256:4fe028537721f277fc3969b0af02abcedef2bff0d027d1826e9055de62d26b33",
    ),
    (
        {"list": [3, 1, 2], "none_value": None},
        "sha256:3243aa9ff74371b3ef14f95d9ae58126e82858561f860ebffe88945589f464e2",
    ),
    (
        {"unicode": "naïve café", "num": -42},
        "sha256:9de5f6acf079bcfe458c40a186f79f9c84fb392fae3e9365d2a211aabe92352e",
    ),
    ([], "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"),
    ({}, "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"),
    (
        {"empty_list": [], "empty_dict": {}},
        "sha256:8600a0d5676331742e3e74e9ff159ebf2e0a0e9384cc9678a178ebd7e15cb3f1",
    ),
]


def test_fixed_hash_fixtures_reproduce_exactly():
    for value, expected_hash in _FIXTURES:
        assert canonical_hash(value) == expected_hash, f"canonicalization drift for {value!r}"
