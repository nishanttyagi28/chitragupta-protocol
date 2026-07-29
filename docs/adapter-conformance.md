# Adapter Conformance Kit (extreme-v2 Phase 18)

Deterministic structural checks that an `EffectAdapter` obeys the contract
in [adapter-authoring.md](adapter-authoring.md). The kit does **not** prove
honesty against a live Stripe/SendGrid/cloud API.

## Entry points

| Symbol | Role |
|---|---|
| `ConformanceScenario` | Request + optional TOCTOU mutate hook |
| `AdapterConformanceKit` / `run_adapter_conformance` | Run the checklist |
| `ConformanceReport` | Named pass/fail results; `raise_if_failed()` |

## Checks

1. **identity** — non-empty `adapter_id` / `adapter_version` within length bounds
2. **prepare_binds_identity** — manifest binds the executing adapter; non-empty
   `effect_type` and `idempotency_key`
3. **preconditions** — returns `PreconditionResult`; optional mutate must make
   the check unsatisfied when `expect_stale_after_mutate=True`
4. **verify_rejects_uncommitted_forged_success** — before `commit`, a forged
   `CommitResult(success=True)` must not yield `matched_expected=True`
5. **commit_shape** — returns `CommitResult` with idempotency key; replay returns
   `CommitResult`
6. **compensation_honesty** — never `succeeded=True` with `attempted=False`
7. **irreversible_compensation** — `IRREVERSIBLE` manifests never report
   compensation `succeeded=True`

## Honesty limits

- Passing the kit means the adapter instance behaved correctly under the
  exercised scenario — not that a production provider is trustworthy.
- Reference adapters (payment simulator, email sandbox, SQLite row) are
  covered by unit tests that run this kit.
- Third-party adapters should run the kit in their own CI with their own
  `ConformanceScenario` request factories.
