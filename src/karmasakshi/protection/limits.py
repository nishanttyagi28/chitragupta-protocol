"""Resource and DoS protection (extreme-v2 Phase 20).

Bounded, fail-closed ceilings for request size and request rate. These are
process-local controls suitable for single-node evaluation and self-host —
not a distributed WAF or multi-instance rate store.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

from karmasakshi.errors import RateLimitExceededError, RequestTooLargeError

DEFAULT_MAX_REQUEST_BYTES = 256 * 1024  # 256 KiB
DEFAULT_API_RATE_LIMIT_PER_MINUTE = 120
WINDOW_SECONDS = 60.0


@dataclass(frozen=True)
class ResourceProtectionPolicy:
    """Explicit resource ceilings (fail closed when exceeded)."""

    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    rate_limit_per_minute: int = DEFAULT_API_RATE_LIMIT_PER_MINUTE
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.max_request_bytes < 1024:
            raise ValueError("max_request_bytes must be >= 1024")
        if self.max_request_bytes > 16 * 1024 * 1024:
            raise ValueError("max_request_bytes must be <= 16 MiB")
        if self.rate_limit_per_minute < 1:
            raise ValueError("rate_limit_per_minute must be >= 1")
        if self.rate_limit_per_minute > 100_000:
            raise ValueError("rate_limit_per_minute must be <= 100000")


def policy_from_env() -> ResourceProtectionPolicy:
    """Load protection policy from env; missing values use safe defaults."""
    max_bytes = DEFAULT_MAX_REQUEST_BYTES
    rate = DEFAULT_API_RATE_LIMIT_PER_MINUTE
    enabled = True
    raw_bytes = os.environ.get("KARMASAKSHI_MAX_REQUEST_BYTES")
    if raw_bytes:
        max_bytes = int(raw_bytes)
    raw_rate = os.environ.get("KARMASAKSHI_API_RATE_LIMIT_PER_MINUTE")
    if raw_rate:
        rate = int(raw_rate)
    raw_enabled = os.environ.get("KARMASAKSHI_RESOURCE_PROTECTION")
    if raw_enabled is not None:
        enabled = raw_enabled.strip().lower() not in ("0", "false", "off", "no")
    return ResourceProtectionPolicy(
        max_request_bytes=max_bytes,
        rate_limit_per_minute=rate,
        enabled=enabled,
    )


def enforce_content_length(content_length: int | None, *, max_bytes: int) -> None:
    """Fail closed when Content-Length exceeds the configured ceiling.

    Missing Content-Length is allowed here (chunked / streaming); callers
    that buffer the full body must enforce after read.
    """
    if content_length is None:
        return
    if content_length < 0:
        raise RequestTooLargeError("negative Content-Length is invalid (fail closed)")
    if content_length > max_bytes:
        raise RequestTooLargeError(
            f"request Content-Length {content_length} exceeds max_request_bytes "
            f"{max_bytes} (fail closed)"
        )


@dataclass
class _Window:
    window_start: float
    count: int


class FixedWindowRateLimiter:
    """Process-local fixed-window rate limiter keyed by client identity."""

    def __init__(self, limit_per_minute: int) -> None:
        if limit_per_minute < 1:
            raise ValueError("limit_per_minute must be >= 1")
        self._limit = limit_per_minute
        self._buckets: dict[str, _Window] = {}
        self._lock = threading.Lock()

    @property
    def limit_per_minute(self) -> int:
        return self._limit

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

    def check(self, client_key: str) -> None:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(client_key)
            if bucket is None or now - bucket.window_start >= WINDOW_SECONDS:
                self._buckets[client_key] = _Window(window_start=now, count=1)
                return
            if bucket.count >= self._limit:
                raise RateLimitExceededError(
                    f"rate limit exceeded ({self._limit} requests/minute); fail closed"
                )
            bucket.count += 1


__all__ = [
    "FixedWindowRateLimiter",
    "ResourceProtectionPolicy",
    "enforce_content_length",
    "policy_from_env",
]
