# Trusted Adapter Registry (extreme-v2 Phase 17)

A versioned allow-list of effect adapters the control plane may invoke.
When `EngineContext.adapter_registry` is set, prepare / commit / verify /
compensate paths **fail closed** on:

- unknown `(adapter_id, adapter_version)` pairs
- revoked registry entries
- effect types outside the declared capability set (forward commit / prepare / verify)

Exact version pins only — no semver ranges, no dynamic plugin discovery.

## Surfaces

| Type | Role |
|---|---|
| `AdapterCapability` | Declared id, version, effect types, environments, idempotency / compensation facts |
| `TrustedAdapterRegistry` | Process-local allow-list with register / revoke / require |
| `build_reference_registry()` | Allow-list for the three shipped reference adapters |
| `facts_from_capability()` | Merge capability declarations into `AssessmentFacts` |
| `EngineContext.adapter_registry` | Optional; when set, engine gates adapter use |

## Invariants

- **#65** Unknown or version-mismatched adapters fail closed when a registry is configured.
- **#66** Effect types outside the declared capability fail closed at prepare/commit/verify.
- **#67** Revoked registry entries fail closed until an operator re-registers explicitly.

## Honesty limits

- The registry is **process-local**. Multi-node deployments must provision the
  same allow-list on each control-plane instance — this is not a consensus
  store.
- Capability facts (`provider_idempotent`, `compensation_feasible`) are
  operator declarations for scoring / documentation, not live provider probes.
- Omitting `adapter_registry` preserves Phases 1–16 behavior (caller-supplied
  adapters are accepted). Evaluation API / public demo wire the reference
  registry by default.
- Compensation commit checks adapter trust (id+version) but not the
  `.compensate` effect-type suffix against the capability list; the
  compensation grant separately binds allowed effect types.
