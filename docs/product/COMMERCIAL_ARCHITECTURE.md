# Commercial Architecture

## Layers

```text
┌─────────────────────────────────────────────────────────┐
│ Control Center (UI) — approvals, timeline, passports      │
├─────────────────────────────────────────────────────────┤
│ Gateway HTTP API — org-scoped effect lifecycle            │
├─────────────────────────────────────────────────────────┤
│ KarmaSakshi Core — protocol engine, grants, audit, crypto │
├─────────────────────────────────────────────────────────┤
│ Effect Adapters — payment simulator / future providers    │
└─────────────────────────────────────────────────────────┘
```

## Tenancy (target)

- Organization is the isolation boundary
- Service credentials are scoped and hashed at rest
- Cross-tenant reads fail closed

**Current protocol core** is still largely single-tenant process-local API state (see `docs/limitations.md`). Commercial Milestone A introduces durable organization models around that core without pretending multi-tenant production isolation is complete until Milestone B tests pass.

## Implementation status

`karmasakshi.gateway` (see [docs/gateway.md](../gateway.md)) implements:

- The durable organization + user model: `Organization`, `GatewayUser`,
  explicit versioned SQLite migrations, and local development
  authentication (PBKDF2, fails closed on cross-organization access).
- The Gateway HTTP API: `/gateway/organizations`, `/gateway/auth/login`,
  org-scoped user management with session tokens.
- The refund vertical slice, wired to a per-organization isolated
  protocol engine (reusing Phase 19's `MultiTenantControlPlane`, so
  "Organization is the isolation boundary" and "cross-tenant reads fail
  closed" above are exercised, not just aspirational): signed
  organization policy activation, propose → assess → approve → commit →
  verify → passport → evidence-pack, plus honest ambiguous-outcome
  recovery and compensation as a separate authorized effect.
- The typed synchronous and asynchronous Python SDK for the complete
  Gateway organization/auth/refund surface.
- The authenticated Control Center at `/control-center/`: a
  server-rendered backend-for-frontend that uses the async SDK against
  the real Gateway API for overview, approvals, exact effect review,
  lifecycle, passports, and audit search. Browser sessions are
  HttpOnly/SameSite, mutating forms are CSRF-protected, and organization
  scope comes from the authenticated user.

Not yet built: durable agent/adapter registries (an agent is currently
just a `principal_id` string) and multi-approver quorum. Docker Compose,
buyer-facing acceptance automation, and real UI media remain before
Milestone A can be claimed complete. See `docs/product/BUILD_STATUS.md`.

## Evaluation modes

| Mode | Purpose |
|---|---|
| Local venv | Developer quickstart |
| Docker Compose | Buyer evaluation without cloud credentials |
| Single-node self-host | Staging |
| Documented production architecture | Guidance only until Enterprise milestone |

## Security defaults

- Fail closed on missing production secrets at startup
- Development credentials clearly labelled temporary
- Never store or log raw API tokens, private keys, or payment PANs
