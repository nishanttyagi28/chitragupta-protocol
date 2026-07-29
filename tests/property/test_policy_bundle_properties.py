from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.intelligence import IntelligencePolicy
from karmasakshi.intelligence.policy import build_policy_bundle, policy_from_bundle_payload

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_ISSUER = Principal(principal_id="policy-admin", principal_type=PrincipalType.HUMAN)

_currency = st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=3, max_size=3)
_thresholds = st.lists(
    st.integers(min_value=0, max_value=10**9), min_size=3, max_size=3, unique=True
).map(sorted)


@st.composite
def _policies(draw: st.DrawFn) -> IntelligencePolicy:
    block_threshold = draw(st.integers(min_value=1, max_value=100))
    review_threshold = draw(st.integers(min_value=0, max_value=block_threshold))
    lo = draw(st.integers(min_value=1, max_value=98))
    mid = draw(st.integers(min_value=lo + 1, max_value=99))
    hi = draw(st.integers(min_value=mid + 1, max_value=100))
    restricted = draw(st.lists(st.text(alphabet="abcdefgh.", min_size=1, max_size=20), max_size=5))
    patterns = draw(st.lists(st.text(alphabet="abcdefgh", min_size=1, max_size=10), max_size=3))
    n_currencies = draw(st.integers(min_value=0, max_value=3))
    amount_thresholds = {}
    for _ in range(n_currencies):
        currency = draw(_currency)
        thresholds = draw(_thresholds)
        if len(set(thresholds)) == 3:
            amount_thresholds[currency] = tuple(thresholds)
    return IntelligencePolicy(
        block_threshold=block_threshold,
        review_threshold=review_threshold,
        risk_level_thresholds=(lo, mid, hi),
        restricted_effect_types=tuple(restricted),
        sensitive_target_patterns=tuple(patterns),
        amount_thresholds=amount_thresholds,
        max_acceptable_failure_rate=draw(
            st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
        ),
    )


@given(_policies())
@settings(max_examples=200, deadline=None)
def test_policy_round_trips_through_bundle_payload_exactly(policy: IntelligencePolicy) -> None:
    bundle = build_policy_bundle(
        policy,
        bundle_id="rt",
        bundle_version="1.0",
        issuer=_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    reconstructed = policy_from_bundle_payload(bundle.payload)
    assert reconstructed.policy_hash() == policy.policy_hash()


@given(_policies())
@settings(max_examples=200, deadline=None)
def test_bundle_hash_stable_across_two_builds_of_same_policy(policy: IntelligencePolicy) -> None:
    b1 = build_policy_bundle(
        policy,
        bundle_id="stable",
        bundle_version="1.0",
        issuer=_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    b2 = build_policy_bundle(
        policy,
        bundle_id="stable",
        bundle_version="1.0",
        issuer=_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    assert b1.canonical_hash() == b2.canonical_hash()


@given(_policies(), st.integers(min_value=1, max_value=10**6))
@settings(max_examples=100, deadline=None)
def test_effective_window_membership_is_consistent(
    policy: IntelligencePolicy, offset_seconds: int
) -> None:
    until = _NOW + timedelta(seconds=offset_seconds)
    bundle = build_policy_bundle(
        policy,
        bundle_id="window",
        bundle_version="1.0",
        issuer=_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
        effective_until=until,
    )
    assert bundle.is_effective_at(_NOW) is True
    assert bundle.is_effective_at(until) is False
    assert bundle.is_effective_at(_NOW - timedelta(seconds=1)) is False
