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

`karmasakshi.gateway` (see [docs/gateway.md](../gateway.md)) implements the
durable organization + user model described above: `Organization`,
`GatewayUser`, explicit versioned SQLite migrations, and local
development authentication (PBKDF2, fails closed on cross-organization
access). Not yet wired into an HTTP API or UI — see
`docs/product/BUILD_STATUS.md` for what remains.

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
