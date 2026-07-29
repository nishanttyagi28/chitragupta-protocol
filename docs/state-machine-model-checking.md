# Bounded State-Machine Model Checking (extreme-v2 Phase 22)

Deterministic, bounded exhaustive checks over the lifecycle
`TRANSITIONS` graph via `check_lifecycle_model()`.

## Checks

1. Transition table consistent with `is_legal_transition`
2. Terminal states have no exits
3. Happy path PROPOSED→…→VERIFIED is legal
4. Bounded path enumeration stays legal
5. All states reachable from PROPOSED
6. COMMITTING is not revocable (invariant #27 structural)

## Honesty

- Finite-graph checker — **not** TLA+/Alloy/SPIN formal verification
- Depth-bounded; does not explore infinite executions
