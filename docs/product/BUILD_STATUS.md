# Product Build Status

_Last updated: 2026-07-29_

| Area | Status |
|---|---|
| Product vision / architecture docs | **Drafted** (this directory) |
| MVP acceptance checklist | Drafted; **not passing** |
| Gateway commercial org model | **Implemented**: durable `Organization`/`GatewayUser` + explicit SQLite migrations + local-dev authentication (`karmasakshi.gateway`, see `docs/gateway.md`). |
| Gateway HTTP API (org bootstrap + login + user management) | **Implemented**: `POST /gateway/organizations`, `POST /gateway/auth/login`, `GET /gateway/auth/me`, org-scoped user CRUD, session tokens, cross-org fail-closed. See `docs/gateway.md`. |
| Gateway HTTP API (refund vertical slice) | **Implemented**: signed policy activation, propose → assess → approve → commit → verify → passport → evidence-pack, honest ambiguous-outcome recovery, compensation as a separate authorized effect -- each organization gets an isolated protocol engine (Phase 19 `MultiTenantControlPlane`). See `docs/gateway.md`. |
| Control Center UI journey | **Implemented**: real server-rendered UI at `/control-center/` using the typed async SDK and Gateway HTTP API; overview, approval inbox, exact before/after, structured risk/policy requirements, approve/deny, commit/verify/recover, lifecycle timeline, Action Passport V2, audit search, strict org isolation, CSRF, safe cookies/logout/errors. See `docs/control-center.md`. |
| Typed Python SDK | **Implemented**: `karmasakshi.sdk` -- `GatewayClient` (sync) and `AsyncGatewayClient` (async), full coverage of the org/auth/refund HTTP surface, typed responses reusing the real server-side pydantic models (`ActionPassport`, `EvidencePack`, `AuditEvent`, ...). See `docs/sdk.md`. |
| Docker Compose evaluation product | Protocol compose may exist; commercial acceptance unfinished |
| README demo GIF/MP4 from commercial UI | Not started |
| Milestone A automated acceptance | Not started -- `tests/integration/test_gateway_refunds.py`, `test_sdk_client.py`, `test_sdk_async_client.py`, and `test_control_center.py` cover the real API/SDK/UI journey and adversarial cases in CI, but there is no standalone, buyer-facing acceptance script yet |
| Milestone B / C | Not started |

## Protocol foundation (blocking / enabling)

- All 25 extreme-v2 phases merged to `main` (see `docs/extreme-v2-build-status.md`)

## Exact next product step

Build the Docker Compose evaluation environment, then a standalone
buyer-facing automated acceptance script that drives the checklist in
`MVP_ACCEPTANCE.md` end to end (today the API/SDK/UI slices are exercised
by `pytest`, not by a dedicated acceptance command), followed by real
screenshots/demo video from the running Control Center and final README
polish.
