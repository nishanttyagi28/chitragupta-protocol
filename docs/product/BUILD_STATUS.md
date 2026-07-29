# Product Build Status

_Last updated: 2026-07-29_

| Area | Status |
|---|---|
| Product vision / architecture docs | **Drafted** (this directory) |
| MVP acceptance checklist | Drafted; **not passing** |
| Gateway commercial org model | **Implemented**: durable `Organization`/`GatewayUser` + explicit SQLite migrations + local-dev authentication (`karmasakshi.gateway`, see `docs/gateway.md`). |
| Gateway HTTP API (org bootstrap + login + user management) | **Implemented**: `POST /gateway/organizations`, `POST /gateway/auth/login`, `GET /gateway/auth/me`, org-scoped user CRUD, session tokens, cross-org fail-closed. See `docs/gateway.md`. |
| Gateway HTTP API (refund vertical slice) | **Implemented**: signed policy activation, propose → assess → approve → commit → verify → passport → evidence-pack, honest ambiguous-outcome recovery, compensation as a separate authorized effect -- each organization gets an isolated protocol engine (Phase 19 `MultiTenantControlPlane`). See `docs/gateway.md`. |
| Control Center UI journey | Partial public demo exists; not commercial MVP |
| Typed Python SDK | Not started |
| Docker Compose evaluation product | Protocol compose may exist; commercial acceptance unfinished |
| README demo GIF/MP4 from commercial UI | Not started |
| Milestone A automated acceptance | Not started -- `tests/integration/test_gateway_refunds.py` covers the journey and adversarial cases in CI, but there is no standalone, buyer-facing acceptance script yet |
| Milestone B / C | Not started |

## Protocol foundation (blocking / enabling)

- All 25 extreme-v2 phases merged to `main` (see `docs/extreme-v2-build-status.md`)

## Exact next product step

Build the Control Center UI (approval inbox, before/after effect view,
timeline, passport viewer, audit explorer) against the refund journey
endpoints now in place, then the typed Python SDK, then the Docker
Compose evaluation environment, then a standalone automated acceptance
script that drives the checklist in `MVP_ACCEPTANCE.md` end to end
(today that checklist is exercised by `pytest`, not by a dedicated buyer-
facing script) plus real screenshots/demo video from the running UI.
