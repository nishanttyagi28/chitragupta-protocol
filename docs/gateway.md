# KarmaSakshi Gateway: Durable Organization Model + HTTP API

`karmasakshi.gateway` is the commercial Milestone A Gateway layer
described in
[docs/product/COMMERCIAL_ARCHITECTURE.md](product/COMMERCIAL_ARCHITECTURE.md):
a durable **organization** model, **local development authentication**
with session tokens, and an HTTP API exposing both — backed by explicit,
versioned SQLite migrations.

This is additive to the open-core protocol. Nothing here changes
`karmasakshi.engine`, `karmasakshi.domain`, or any existing security
invariant (see [docs/security-model.md](security-model.md)).

## What's here

- `Organization` — an isolation boundary (`org_id`, `name`, `status`:
  `active`/`suspended`).
- `GatewayUser` — a team member of one organization (`user_id`,
  `org_id`, `email`, `display_name`, `role`). Never carries password
  material.
- `GatewayStore` — SQLite-backed CRUD for both, plus `authenticate()`.

```python
from karmasakshi.gateway import GatewayStore, GatewayUserRole

store = GatewayStore("gateway.db")
org = store.create_organization("acme", "Acme Corp")
user = store.create_user(
    user_id="u1",
    org_id=org.org_id,
    email="alice@acme.com",
    display_name="Alice",
    password="a-real-password",
    role=GatewayUserRole.OWNER,
)
authenticated = store.authenticate(
    org_id=org.org_id, email="alice@acme.com", password="a-real-password"
)
```

## Explicit migrations

Unlike the protocol core's single-table SQLite backends (grants, audit,
lifecycle, outbox), which use an idempotent
`CREATE TABLE IF NOT EXISTS` script because each owns one stable table,
the Gateway's schema is expected to evolve across commercial milestones.
`karmasakshi.gateway.migrations` tracks exactly which migrations a given
database file has applied in a `schema_migrations` table, and
`apply_migrations()` (run automatically by `GatewayStore.__init__`)
applies only what's missing, in order, one transaction per migration. A
migration that fails rolls back and stops — later migrations never apply
out of order over a failed one.

## Authentication: what this is and is not

- Passwords are hashed with PBKDF2-HMAC-SHA256 (200,000 iterations, a
  16-byte random salt per user) — a real key-derivation function, not a
  toy. Password hashes are never equal to, nor recoverable from, the
  plaintext.
- `authenticate()` scopes lookup by `org_id` + `email` and fails closed
  (a single `GatewayAuthenticationError`, never distinguishing *why*) on:
  unknown organization, suspended organization, unknown email in that
  organization, or a wrong password. A user of one organization cannot
  authenticate against a different organization even with the exact
  right email + password.
- **This is local development authentication only.** There is no SSO, no
  MFA, and no server-enforced RBAC yet (`GatewayUserRole` is metadata,
  not currently checked by any authorization decision) — those are
  Milestone B/C. See [docs/limitations.md](limitations.md) and
  [docs/product/SECURITY_FAQ.md](product/SECURITY_FAQ.md).

## HTTP API

Mounted under `/gateway` in the same FastAPI app as the protocol control
plane (`karmasakshi.api.app.create_app`) — a running Gateway server is
one process exposing both. See `karmasakshi.gateway.api`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/gateway/organizations` | Platform (`require_auth`: dev-mode/token) | Bootstrap an organization + its first (owner) user in one call |
| POST | `/gateway/auth/login` | None (this *is* the auth step) | Authenticate `org_id` + `email` + `password`, issue a session token |
| GET | `/gateway/auth/me` | Gateway session | Resolve the bearer token to its authenticated user |
| GET | `/gateway/organizations/{org_id}` | Gateway session (same org) | Fetch organization details |
| GET | `/gateway/organizations/{org_id}/users` | Gateway session (same org) | List an organization's users |
| POST | `/gateway/organizations/{org_id}/users` | Gateway session (same org) | Register an additional user in that organization |

Organization *creation* is deliberately gated by the **platform**
auth check (the same `KARMASAKSHI_API_DEV_MODE` / `KARMASAKSHI_API_TOKEN`
mechanism the rest of the control plane uses) rather than a Gateway
session, because there is no user yet to hold one. Every other
org-scoped endpoint requires a valid Gateway session token
(`Authorization: Bearer <session_token>` from `/gateway/auth/login`) and
independently re-checks that the session's user actually belongs to the
`org_id` in the URL (`assert_user_belongs_to_organization`) — a valid
session for organization A returns `403` against organization B's
endpoints, never silently reading across the boundary.

Sessions are issued and validated by `GatewaySessionStore`: a random
32-byte URL-safe token, a 12-hour default TTL, checked and lazily evicted
on every lookup (no silent renewal — an expired token is treated
identically to an unknown one).

## Known limitations

- Single-node SQLite, same posture as the protocol core's other SQLite
  backends: safe for multiple processes sharing one database file under
  SQLite's writer lock, not a multi-node distributed store.
- No RBAC enforcement, no SSO yet (`GatewayUserRole` is metadata only).
- **Sessions are process-local, in-memory, non-durable** — restarting
  the Gateway process invalidates every session (users must log in
  again). Horizontally scaling the Gateway across multiple processes
  would need a shared session backend (Redis or similar); that is
  explicitly deferred to Milestone B.
- No endpoint yet to revoke a session (logout), rotate/reset a password,
  or remove a user.
- Not yet wired into the refund vertical slice (agent/adapter/policy
  registration, propose → assess → approve → commit → verify → passport)
  or the Control Center UI — those are the next Milestone A slices (see
  `docs/product/BUILD_STATUS.md`).
