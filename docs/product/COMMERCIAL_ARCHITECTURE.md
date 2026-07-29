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

Not yet built: the Control Center UI, durable agent/adapter registries
(an agent is currently just a `principal_id` string), multi-approver
quorum, and the typed SDK. See `docs/product/BUILD_STATUS.md` for what
remains before `docs/product/MVP_ACCEPTANCE.md` can be automated end to
end.

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
