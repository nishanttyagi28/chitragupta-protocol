# Product Build Status

_Last updated: 2026-07-29_

| Area | Status |
|---|---|
| Product vision / architecture docs | **Drafted** (this directory) |
| MVP acceptance checklist | **Passing**: 25 buyer-visible checks through API, SDK, and authenticated UI; standalone JSON report plus real-server integration coverage. |
| Gateway commercial org model | **Implemented**: durable `Organization`/`GatewayUser`, org-scoped agent/adapter inventory, explicit SQLite migrations, and local-evaluation authentication (`karmasakshi.gateway`, see `docs/gateway.md`). |
| Gateway HTTP API (org bootstrap + login + user management) | **Implemented**: `POST /gateway/organizations`, `POST /gateway/auth/login`, `GET /gateway/auth/me`, org-scoped user CRUD, session tokens, cross-org fail-closed. See `docs/gateway.md`. |
| Gateway HTTP API (refund vertical slice) | **Implemented**: signed policy activation, propose → assess → approve → commit → verify → passport → evidence-pack, honest ambiguous-outcome recovery, compensation as a separate authorized effect -- each organization gets an isolated protocol engine (Phase 19 `MultiTenantControlPlane`). See `docs/gateway.md`. |
| Control Center UI journey | **Implemented**: real server-rendered UI at `/control-center/` using the typed async SDK and Gateway HTTP API; overview, approval inbox, exact before/after, structured risk/policy requirements, approve/deny, commit/verify/recover, lifecycle timeline, Action Passport V2, audit search, strict org isolation, CSRF, safe cookies/logout/errors. See `docs/control-center.md`. |
| Typed Python SDK | **Implemented**: `karmasakshi.sdk` -- `GatewayClient` (sync) and `AsyncGatewayClient` (async), full coverage of the org/auth/refund HTTP surface, typed responses reusing the real server-side pydantic models (`ActionPassport`, `EvidencePack`, `AuditEvent`, ...). See `docs/sdk.md`. |
| Docker Compose evaluation product | **Implemented**: loopback-only API, named data volume, health-gated acceptance profile, machine-readable report, and dedicated CI job. |
| README demo GIF/MP4 from commercial UI | **Implemented**: authenticated real-browser screenshots plus reproducible 38-second MP4 / 20-second GIF. |
| Milestone A automated acceptance | **Implemented and passing locally**: `karmasakshi-acceptance` completes 25 checks; focused tests include real uvicorn, UI, SDK, security, quorum, ambiguity, and isolation coverage. Compose execution is additionally required green in PR CI. |
| Milestone B / C | Not started |

## Protocol foundation (blocking / enabling)

- All 25 extreme-v2 phases merged to `main` (see `docs/extreme-v2-build-status.md`)

## Exact next product step

Milestone A implementation is complete. Do not begin Milestone B or the
saved 40x expansion from this branch. The next authorized action is
release review of the merged Milestone A artifact and its documented
limitations.
