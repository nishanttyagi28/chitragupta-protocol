"""Tests for resource / DoS protection (Phase 20)."""

from __future__ import annotations

import pytest

from karmasakshi.errors import RateLimitExceededError, RequestTooLargeError
from karmasakshi.protection.limits import (
    FixedWindowRateLimiter,
    ResourceProtectionPolicy,
    enforce_content_length,
    policy_from_env,
)


def test_enforce_content_length_fail_closed():
    enforce_content_length(None, max_bytes=1000)
    enforce_content_length(100, max_bytes=1000)
    with pytest.raises(RequestTooLargeError):
        enforce_content_length(1001, max_bytes=1000)
    with pytest.raises(RequestTooLargeError):
        enforce_content_length(-1, max_bytes=1000)


def test_rate_limiter_trips():
    limiter = FixedWindowRateLimiter(3)
    limiter.check("client-a")
    limiter.check("client-a")
    limiter.check("client-a")
    with pytest.raises(RateLimitExceededError):
        limiter.check("client-a")
    limiter.check("client-b")  # independent key
    limiter.reset()
    limiter.check("client-a")


def test_policy_bounds():
    with pytest.raises(ValueError):
        ResourceProtectionPolicy(max_request_bytes=10)
    with pytest.raises(ValueError):
        ResourceProtectionPolicy(rate_limit_per_minute=0)
    p = ResourceProtectionPolicy()
    assert p.enabled is True


def test_policy_from_env(monkeypatch):
    monkeypatch.setenv("KARMASAKSHI_MAX_REQUEST_BYTES", "4096")
    monkeypatch.setenv("KARMASAKSHI_API_RATE_LIMIT_PER_MINUTE", "5")
    monkeypatch.setenv("KARMASAKSHI_RESOURCE_PROTECTION", "1")
    p = policy_from_env()
    assert p.max_request_bytes == 4096
    assert p.rate_limit_per_minute == 5
    monkeypatch.setenv("KARMASAKSHI_RESOURCE_PROTECTION", "off")
    assert policy_from_env().enabled is False


def test_api_middleware_rejects_oversized(monkeypatch):
    from fastapi.testclient import TestClient

    from karmasakshi.api.app import create_app
    from karmasakshi.api.auth import DEV_MODE_ENV

    monkeypatch.setenv(DEV_MODE_ENV, "1")
    monkeypatch.setenv("KARMASAKSHI_MAX_REQUEST_BYTES", "2048")
    monkeypatch.setenv("KARMASAKSHI_API_RATE_LIMIT_PER_MINUTE", "1000")
    app = create_app()
    client = TestClient(app)
    # Oversized Content-Length should 413 before body is fully processed.
    resp = client.post(
        "/principals",
        content=b"{}",
        headers={"content-length": "99999", "content-type": "application/json"},
    )
    assert resp.status_code == 413
