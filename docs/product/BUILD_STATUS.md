# Product Build Status

_Last updated: 2026-07-30_

| Area | Status |
|---|---|
| Product vision / architecture docs | **Drafted** (this directory) |
| MVP acceptance checklist | **Passing**: 25 buyer-visible checks through API, SDK, and authenticated UI; standalone JSON report plus real-server integration coverage. |
| Gateway commercial org model | **Implemented**: durable `Organization`/`GatewayUser`, org-scoped agent/adapter inventory, explicit SQLite migrations, and local-evaluation authentication (`karmasakshi.gateway`, see `docs/gateway.md`). |
| Gateway HTTP API (org bootstrap + login + user management) | **Implemented**: `POST /gateway/organizations`, `POST /gateway/auth/login`, `GET /gateway/auth/me`, org-scoped user CRUD, session tokens, cross-org fail-closed. See `docs/gateway.md`. |
| Gateway HTTP API (refund vertical slice) | **Implemented**: signed policy activation, propose → assess → approve → commit → verify → passport → evidence-pack, honest ambiguous-outcome recovery, compensation as a separate authorized effect -- each organization gets an isolated protocol engine (Phase 19 `MultiTenantControlPlane`). Restart rehydrates refund-journey state, proposal-time policy binding, and per-tenant signing keys. See `docs/gateway.md`. |
| Control Center UI journey | **Implemented**: real server-rendered UI at `/control-center/` using the typed async SDK and Gateway HTTP API; overview, approval inbox, exact before/after, structured risk/policy requirements, approve/deny, commit/verify/recover, lifecycle timeline, Action Passport V2, audit search, strict org isolation, CSRF, safe cookies/logout/errors. See `docs/control-center.md`. |
| Typed Python SDK | **Implemented**: `karmasakshi.sdk` -- `GatewayClient` (sync) and `AsyncGatewayClient` (async), full coverage of the org/auth/refund HTTP surface, typed responses reusing the real server-side pydantic models (`ActionPassport`, `EvidencePack`, `AuditEvent`, ...). See `docs/sdk.md`. |
| Docker Compose evaluation product | **Implemented**: loopback-only API, named data volume, health-gated acceptance profile, machine-readable report, and dedicated CI job. Local Docker not available in the latest audit environment; Compose acceptance is verified by required CI. |
| README demo GIF/MP4 from commercial UI | **Implemented**: authenticated real-browser screenshots plus reproducible 38-second MP4 / 20-second GIF. |
| Milestone A automated acceptance | **Implemented and passing locally**: `karmasakshi-acceptance` completes 25/25 checks; focused tests include real uvicorn, UI, SDK, security, quorum, ambiguity, restart durability, signing-key fail-closed, and isolation coverage. Compose execution is additionally required green in PR CI. |
| Release-audit remediation | **Complete for Critical/High/Medium** original findings plus post-remediation RA-002 residual, policy-binding timing, signing-key durability, and fail-closed missing/corrupt/mismatched key material. Original `RELEASE_AUDIT.md` NO-GO baseline preserved. |
| Milestone B / C | Not started |

## Quality gates (verified 2026-07-30, branch `fix/ra002-and-policy-binding-gaps`)

| Gate | Result |
|---|---|
| Full suite | `1049 passed, 8 skipped` |
| Coverage | `90.50%` (`--cov-fail-under=90`) |
| ruff / mypy / bandit / pip-audit | Clean / no known vulnerabilities |
| build + twine | Both artifacts PASSED |
| Buyer acceptance | 25/25 PASS |
| Docker Compose acceptance | Required CI job (local Docker unavailable) |

## Protocol foundation (blocking / enabling)

- All 25 extreme-v2 phases merged to `main` (see `docs/extreme-v2-build-status.md`)

## Exact next product step

Milestone A is evaluation-ready self-hosted software after release-audit
remediation. Do not begin Milestone B or the saved 40x expansion from this
branch. The next authorized action is merge of the post-remediation PR once
required CI is fully green, then release review of the merged artifact and
its documented limitations.
