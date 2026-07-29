# Saga Orchestration

Extreme-v2 Phase 8 adds a **thin durable saga coordinator** over a verified
`CausalEffectGraph`. A saga is multi-step, **multi-grant** orchestration:

- each forward step still requires its own sealed manifest and
  `ExecutionGrant` (typically via `authorize_plan`)
- step order is the deterministic topological order of the bound graph
- outcomes are honest: at-most-once per step, ambiguous outcomes block
  blind retry, compensation uses the Phase 7 path in reverse

Saga orchestration never claims exactly-once execution across providers.

## Run statuses

| Status | Meaning |
|---|---|
| `pending` / `running` | Forward progress |
| `awaiting_recovery` | A step is `ambiguous`; recover before continuing |
| `compensating` | Reverse-order Phase 7 compensation of committed/verified steps |
| `completed` | All forward steps verified |
| `failed_partial` | Compensation finished; never claimed as atomic rollback |
| `aborted` | Stopped before any external commit |

## Engine API

- `begin_saga(graph)` — verify graph, build deterministic plan, start run
- `authorize_saga_step(run_id, sealed, graph, …)` — cursor-gated `authorize_plan`
- `commit_saga_step(...)` — cursor-gated `commit`; refuses AMBIGUOUS re-commit
- `verify_saga_step(...)` — advances cursor on matched verification
- `recover_saga_step(...)` — wraps `recover_ambiguous_commit`
- `record_saga_compensation(...)` — records Phase 7 status triad for reverse cursor

Durability in this phase means **audit events + process-local run state**
(same pattern as lifecycle records). Cross-process durable saga storage is
Phase 13.

## Explicitly deferred

- multi-node single-grant execution
- parallel step execution
- automatic background reconciler
- distributed exactly-once / 2PC

## Security invariants

See `#46`–`#49` in [docs/security-model.md](security-model.md).
