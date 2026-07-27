# FastAPI Control Plane

Optional (`pip install chitragupta-protocol[api]`). `chitragupta.api.create_app()`
builds a FastAPI app; `chitragupta.web.console` adds a server-rendered
local console at `/console/`.

## Running it

```python
from chitragupta.api import create_app
import uvicorn

app = create_app()  # local dev: wires up the 3 reference adapters automatically
uvicorn.run(app, host="127.0.0.1", port=8000)
```

For production, pass your own `ApiState` (real keys, real adapters) rather
than relying on `build_default_state()`, which is meant for local
development and demos.

## Authentication

**Fail closed by default.** Every route except `/health` and `/ready`
requires either:

- `CHITRAGUPTA_API_DEV_MODE=1` set explicitly (unauthenticated local dev —
  the OpenAPI description and the console's base template both label this
  visibly), **or**
- `CHITRAGUPTA_API_TOKEN=<token>` set, and every request carrying
  `Authorization: Bearer <token>`.

If dev mode is off and `CHITRAGUPTA_API_TOKEN` is unset, the server
returns `500` on every authenticated route rather than silently serving
without authentication — see `chitragupta.api.auth.require_auth` and
`tests/integration/test_api.py::TestAuthEnforcement`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness, no auth |
| GET | `/ready` | Readiness: dev-mode flag, kill-switch state, audit chain status |
| POST | `/principals` | Register a principal |
| GET | `/principals` | List registered principals |
| POST | `/manifests/prepare` | Prepare + seal a manifest via a reference adapter |
| GET | `/manifests` | List all sealed manifests + lifecycle state |
| GET | `/manifests/{id}` | Inspect one manifest + its seal + grant ids |
| POST | `/manifests/{id}/approve` | Issue an `ExecutionGrant` (invariant #30 still enforced) |
| POST | `/manifests/{id}/deny` | Audit-log a denial; never issues a grant |
| POST | `/grants/{id}/revoke` | Revoke a grant |
| POST | `/manifests/{id}/execute` | Commit (blocked with `503` if the kill switch is engaged) |
| POST | `/manifests/{id}/verify` | Independently verify the outcome |
| GET | `/audit` | Full audit timeline |
| GET | `/audit/verify` | Verify the hash chain |
| GET | `/passports/{id}?fmt=json\|html\|markdown` | Action Passport |
| GET | `/kill-switch` | Current status |
| POST | `/kill-switch/engage` / `/disengage` | Emergency stop for `/execute` |

Full request/response schemas: `chitragupta.api.schemas`, or the live
OpenAPI JSON at `/openapi.json` (interactive docs at `/docs`).

## Local console

`/console/` — dashboard (pending approvals, kill switch, audit integrity),
`/console/manifests/{id}` (before/after fields, approve/deny HTML forms),
`/console/grants` (active/revoked, delegation lineage via the Parent
column), `/console/audit` (timeline). Plain server-rendered HTML, no
JavaScript build step — forms POST directly to console routes, which share
the same auth dependency as the JSON API.

## State model

`ApiState` is process-local (see `docs/storage-semantics.md` for the
underlying store/audit backends it wires up). There is no built-in
horizontal scaling story beyond what a shared Redis grant store + shared
audit backend would require — this control plane is a reference
implementation, not a scaled-out production service.
