# Resource and DoS Protection (extreme-v2 Phase 20)

Process-local request size and rate ceilings for the control-plane API.

## Surfaces

| Type | Role |
|---|---|
| `ResourceProtectionPolicy` | `max_request_bytes`, `rate_limit_per_minute`, `enabled` |
| `FixedWindowRateLimiter` | Per-client fixed-window counter |
| `enforce_content_length` | Fail closed on oversized `Content-Length` |
| `ResourceProtectionMiddleware` | ASGI middleware wired into `create_app` |
| `policy_from_env` | `KARMASAKSHI_MAX_REQUEST_BYTES`, `KARMASAKSHI_API_RATE_LIMIT_PER_MINUTE`, `KARMASAKSHI_RESOURCE_PROTECTION` |

Defaults: 256 KiB body ceiling, 120 requests/minute/client. `/health` and
`/ready` are exempt from rate limiting.

## Invariants

- **#71** Oversized requests fail closed (HTTP 413 / `RequestTooLargeError`).
- **#72** Clients exceeding the configured rate fail closed (HTTP 429 /
  `RateLimitExceededError`).

## Honesty limits

- Process-local only — not a shared Redis rate store or WAF.
- Missing `Content-Length` is not rejected at the middleware layer
  (chunked bodies); operators should still terminate TLS/proxy with a
  body size limit in production.
- Public demo retains its separate demo rate limiter
  (`KARMASAKSHI_DEMO_RATE_LIMIT_PER_MINUTE`).
