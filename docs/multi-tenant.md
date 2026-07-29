# Multi-tenant Control Plane (extreme-v2 Phase 19)

Process-local tenant isolation for the control plane. Organization /
`tenant_id` is the isolation boundary.

## Surfaces

| Type | Role |
|---|---|
| `Tenant` | `tenant_id`, display name, `active` / `suspended` |
| `TenantRegistry` | Process-local allow-list; unknown/suspended fail closed |
| `MultiTenantControlPlane` | Per-tenant isolated `ApiState` partitions |
| `EngineContext.tenant_id` | Optional engine binding; policy bundles must match |
| `assert_tenant_match` / `require_active_tenant` | Fail-closed helpers |

## Invariants

- Cross-tenant policy or resource access fails closed when tenant
  context is configured (one side set and the other missing, or both set
  and unequal) — invariant **#69**.
- Unknown or suspended tenants fail closed — invariant **#70**.

## Honesty limits

- Process-local isolation only — not a distributed multi-region directory.
- Omitting `EngineContext.tenant_id` preserves legacy single-tenant behaviour.
- `AssessmentFacts.cross_tenant` remains an advisory scoring input; this
  phase enforces isolation at the control-plane / policy-binding layer.
- Commercial Gateway org models (Milestone A/B) build on this foundation
  and must still pass their own acceptance tests before claiming MVP.
