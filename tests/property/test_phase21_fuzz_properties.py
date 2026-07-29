"""Phase 21 adversarial / fuzz coverage for tenant isolation and resource limits."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from karmasakshi.errors import RateLimitExceededError, RequestTooLargeError, TenantIsolationError
from karmasakshi.protection.limits import FixedWindowRateLimiter, enforce_content_length
from karmasakshi.tenant.enforce import assert_tenant_match

_id = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789._:-"),
    min_size=1,
    max_size=32,
).filter(lambda s: s[0].isalnum())


@given(a=_id, b=_id)
@settings(max_examples=100)
def test_tenant_match_is_symmetric_fail_closed(a: str, b: str) -> None:
    if a == b:
        assert_tenant_match(expected=a, presented=b)
    else:
        with pytest.raises(TenantIsolationError):
            assert_tenant_match(expected=a, presented=b)
        with pytest.raises(TenantIsolationError):
            assert_tenant_match(expected=b, presented=a)


@given(tenant=_id)
@settings(max_examples=50)
def test_tenant_uncertainty_always_fails(tenant: str) -> None:
    with pytest.raises(TenantIsolationError):
        assert_tenant_match(expected=tenant, presented=None)
    with pytest.raises(TenantIsolationError):
        assert_tenant_match(expected=None, presented=tenant)


@given(
    size=st.integers(min_value=0, max_value=10_000),
    ceiling=st.integers(min_value=1, max_value=5_000),
)
@settings(max_examples=100)
def test_content_length_enforcement_is_monotonic(size: int, ceiling: int) -> None:
    if size <= ceiling:
        enforce_content_length(size, max_bytes=ceiling)
    else:
        with pytest.raises(RequestTooLargeError):
            enforce_content_length(size, max_bytes=ceiling)


@given(limit=st.integers(min_value=1, max_value=20), extra=st.integers(min_value=1, max_value=5))
@settings(max_examples=50)
def test_rate_limiter_never_over_admits(limit: int, extra: int) -> None:
    limiter = FixedWindowRateLimiter(limit)
    for _ in range(limit):
        limiter.check("client")
    for _ in range(extra):
        with pytest.raises(RateLimitExceededError):
            limiter.check("client")
