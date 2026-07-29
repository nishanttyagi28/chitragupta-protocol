# KarmaSakshi Gateway: Durable Organization Model

`karmasakshi.gateway` is the first slice of the commercial Milestone A
Gateway layer described in
[docs/product/COMMERCIAL_ARCHITECTURE.md](product/COMMERCIAL_ARCHITECTURE.md):
a durable **organization** model plus **local development
authentication**, backed by explicit, versioned SQLite migrations.

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
  MFA, no session/token issuance, and no server-enforced RBAC yet
  (`GatewayUserRole` is metadata, not currently checked by any
  authorization decision) — those are Milestone B/C. See
  [docs/limitations.md](limitations.md) and
  [docs/product/SECURITY_FAQ.md](product/SECURITY_FAQ.md).

## Known limitations

- Single-node SQLite, same posture as the protocol core's other SQLite
  backends: safe for multiple processes sharing one database file under
  SQLite's writer lock, not a multi-node distributed store.
- No RBAC enforcement, no SSO, no session/token management yet.
- `GatewayStore` is not yet wired into the HTTP Gateway API or Control
  Center UI — those are the next Milestone A slices (see
  `docs/product/BUILD_STATUS.md`).
