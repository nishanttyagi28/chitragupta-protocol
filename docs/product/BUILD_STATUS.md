# Product Build Status

_Last updated: 2026-07-29_

| Area | Status |
|---|---|
| Product vision / architecture docs | **Drafted** (this directory) |
| MVP acceptance checklist | Drafted; **not passing** |
| Gateway commercial org model | **Implemented**: durable `Organization`/`GatewayUser` + explicit SQLite migrations + local-dev authentication (`karmasakshi.gateway`, see `docs/gateway.md`). Not yet wired to an HTTP API. |
| Gateway HTTP API (refund vertical slice) | Not started |
| Control Center UI journey | Partial public demo exists; not commercial MVP |
| Typed Python SDK | Not started |
| Docker Compose evaluation product | Protocol compose may exist; commercial acceptance unfinished |
| README demo GIF/MP4 from commercial UI | Not started |
| Milestone A automated acceptance | Not started |
| Milestone B / C | Not started |

## Protocol foundation (blocking / enabling)

- All 25 extreme-v2 phases merged to `main` (see `docs/extreme-v2-build-status.md`)

## Exact next product step

Wire `karmasakshi.gateway`'s `GatewayStore` into a Gateway HTTP API
(agent/adapter/policy registration, refund proposal → assessment →
approval → commit → verify → passport, all org-scoped), then the refund
vertical slice UI, then an automated acceptance test that drives the
checklist in `MVP_ACCEPTANCE.md`.
