"""ASGI middleware applying Phase 20 resource protection to the API."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from karmasakshi.errors import RateLimitExceededError, RequestTooLargeError
from karmasakshi.protection.limits import (
    FixedWindowRateLimiter,
    ResourceProtectionPolicy,
    enforce_content_length,
)

# Paths exempt from rate limiting (liveness/readiness).
_EXEMPT_PREFIXES = ("/health", "/ready", "/metrics")


class ResourceProtectionMiddleware:
    """Starlette pure-ASGI middleware for body size + rate limits."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        policy: ResourceProtectionPolicy | None = None,
        limiter: FixedWindowRateLimiter | None = None,
    ) -> None:
        self.app = app
        self.policy = policy or ResourceProtectionPolicy()
        self.limiter = limiter or FixedWindowRateLimiter(self.policy.rate_limit_per_minute)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.policy.enabled:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        path = request.url.path
        if any(path == p or path.startswith(p + "/") for p in _EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return

        try:
            raw_len = request.headers.get("content-length")
            content_length = int(raw_len) if raw_len is not None else None
            enforce_content_length(content_length, max_bytes=self.policy.max_request_bytes)
            client = request.client.host if request.client else "unknown"
            self.limiter.check(client)
        except RequestTooLargeError as exc:
            response = JSONResponse({"detail": str(exc)}, status_code=413)
            await response(scope, receive, send)
            return
        except RateLimitExceededError as exc:
            response = JSONResponse({"detail": str(exc)}, status_code=429)
            await response(scope, receive, send)
            return
        except ValueError:
            response = JSONResponse(
                {"detail": "invalid Content-Length header (fail closed)"},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


__all__ = ["ResourceProtectionMiddleware"]
