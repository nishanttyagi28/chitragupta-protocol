# FastAPI Control Plane

Optional (`pip install karmasakshi-protocol[api]`). `karmasakshi.api.create_app()`
builds a FastAPI app; `karmasakshi.web.console` adds a server-rendered
local console at `/console/`.

## Running it

```python
from karmasakshi.api import create_app
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

- `KARMASAKSHI_API_DEV_MODE=1` set explicitly (unauthenticated local dev —
  the OpenAPI description and the console's base template both label this
  visibly), **or**
- `KARMASAKSHI_API_TOKEN=<token>` set, and every request carrying
  `Authorization: Bearer <token>`.

If dev mode is off and `KARMASAKSHI_API_TOKEN` is unset, the server
returns `500` on every authenticated route rather than silently serving
without authentication — see `karmasakshi.api.auth.require_auth` and
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
| POST | `/manifests/{id}/assess` | Run the Effect Intelligence Engine, record `EffectAssessment` (advisory only -- see docs/effect-intelligence.md) |
| GET | `/manifests/{id}/assessment` | Fetch the most recent assessment recorded for a manifest |
| POST | `/manifests/{id}/approve` | Issue an `ExecutionGrant` (invariant #30 still enforced); optional `policy_bundle_id` binds a signed policy bundle's hash into the grant |
| POST | `/manifests/{id}/deny` | Audit-log a denial; never issues a grant |
| POST | `/policy/bundles` | Build, sign, and store a policy bundle (see docs/policy-bundles.md) |
| GET | `/policy/bundles/{id}` | Fetch a stored sealed policy bundle |
| POST | `/policy/bundles/{id}/verify` | Re-verify a stored bundle's signature/integrity/window |
| POST | `/grants/{id}/revoke` | Revoke a grant |
| POST | `/manifests/{id}/execute` | Commit (blocked with `503` if the kill switch is engaged); if the grant is policy-bundle-bound, the same `policy_bundle_id` must be supplied or the commit fails closed |
| POST | `/manifests/{id}/verify` | Independently verify the outcome |
| GET | `/audit` | Full audit timeline |
| GET | `/audit/verify` | Verify the hash chain |
| GET | `/passports/{id}?fmt=json\|html\|markdown` | Action Passport |
| GET | `/kill-switch` | Current status |
| POST | `/kill-switch/engage` / `/disengage` | Emergency stop for `/execute` |

Full request/response schemas: `karmasakshi.api.schemas`, or the live
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
