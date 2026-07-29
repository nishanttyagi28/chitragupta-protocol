# Product Build Status

_Last updated: 2026-07-29_

| Area | Status |
|---|---|
| Product vision / architecture docs | **Drafted** (this directory) |
| MVP acceptance checklist | Drafted; **not passing** |
| Gateway commercial org model | **Implemented**: durable `Organization`/`GatewayUser` + explicit SQLite migrations + local-dev authentication (`karmasakshi.gateway`, see `docs/gateway.md`). |
| Gateway HTTP API (org bootstrap + login + user management) | **Implemented**: `POST /gateway/organizations`, `POST /gateway/auth/login`, `GET /gateway/auth/me`, org-scoped user CRUD, session tokens, cross-org fail-closed. See `docs/gateway.md`. |
| Gateway HTTP API (refund vertical slice) | Not started -- agent/adapter/policy registration, propose → assess → approve → commit → verify → passport, org-scoped |
| Control Center UI journey | Partial public demo exists; not commercial MVP |
| Typed Python SDK | Not started |
| Docker Compose evaluation product | Protocol compose may exist; commercial acceptance unfinished |
| README demo GIF/MP4 from commercial UI | Not started |
| Milestone A automated acceptance | Not started |
| Milestone B / C | Not started |

## Protocol foundation (blocking / enabling)

- All 25 extreme-v2 phases merged to `main` (see `docs/extreme-v2-build-status.md`)

## Exact next product step

Extend the Gateway HTTP API with the refund vertical slice: org-scoped
agent/adapter registration, signed organization policy activation, and
refund proposal → assessment → approval → commit → verify → passport
endpoints wired to the existing `KarmaSakshiEngine` per organization.
Then the Control Center UI, then an automated acceptance test that
drives the checklist in `MVP_ACCEPTANCE.md`.
