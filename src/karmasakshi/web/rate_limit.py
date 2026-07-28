"""A minimal in-memory per-client rate limiter for the public demo surface.

Deliberately simple: a fixed-window counter per client IP, held in process
memory. This is *not* meant to defend a multi-instance production
deployment against a determined attacker (that would need a shared store
such as Redis) -- it exists to keep the free-tier public sandbox usable and
to bound how much load any one visitor can generate, per invariant "add
reasonable input limits and rate limits" in docs/deployment.md.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request

RATE_LIMIT_ENV = "KARMASAKSHI_DEMO_RATE_LIMIT_PER_MINUTE"
DEFAULT_LIMIT_PER_MINUTE = 30
WINDOW_SECONDS = 60.0


@dataclass
class _Window:
    window_start: float
    count: int


class RateLimiter:
    def __init__(self, limit_per_minute: int | None = None) -> None:
        self._limit = limit_per_minute or _configured_limit()
        self._buckets: dict[str, _Window] = {}
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

    def check(self, client_key: str) -> None:
        now = time.monotonic()
        with self._lock:
            window = self._buckets.get(client_key)
            if window is None or (now - window.window_start) >= WINDOW_SECONDS:
                self._buckets[client_key] = _Window(window_start=now, count=1)
                return
            if window.count >= self._limit:
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"rate limit exceeded ({self._limit} requests/minute on the public "
                        "demo sandbox); please wait a moment and try again"
                    ),
                )
            window.count += 1


def _configured_limit() -> int:
    raw = os.environ.get(RATE_LIMIT_ENV)
    if not raw:
        return DEFAULT_LIMIT_PER_MINUTE
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_LIMIT_PER_MINUTE


_limiter = RateLimiter()


def rate_limit_dependency(request: Request) -> None:
    client_key = request.client.host if request.client else "unknown"
    _limiter.check(client_key)


def reset_rate_limiter() -> None:
    """Clear all rate-limit buckets. Used between test cases so one test's
    request volume cannot cause another test to see spurious 429s."""
    _limiter.reset()


__all__ = ["RateLimiter", "rate_limit_dependency", "reset_rate_limiter"]
