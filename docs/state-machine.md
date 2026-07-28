# The Lifecycle State Machine

Defined in `state_machine/states.py`. States and transitions are an
explicit graph (`TRANSITIONS: dict[LifecycleState, frozenset[LifecycleState]]`)
— there is no implicit "anything goes" fallback. An illegal transition
raises `IllegalTransitionError` deterministically and performs no external
effect; the attempt is still recorded in the audit journal
(`decision="blocked_illegal_transition"`).

## States

`PROPOSED`, `PREPARED`, `SEALED`, `AUTHORIZED`, `COMMITTING`, `COMMITTED`,
`VERIFIED`, `FAILED`, `REVOKED`, `EXPIRED`, `COMPENSATING`, `COMPENSATED`.

## Transition table

| From | Legal targets |
|---|---|
| `PROPOSED` | `PREPARED`, `FAILED`, `REVOKED` |
| `PREPARED` | `SEALED`, `FAILED`, `REVOKED`, `EXPIRED` |
| `SEALED` | `AUTHORIZED`, `FAILED`, `REVOKED`, `EXPIRED` |
| `AUTHORIZED` | `COMMITTING`, `FAILED`, `REVOKED`, `EXPIRED` |
| `COMMITTING` | `COMMITTED`, `FAILED` |
| `COMMITTED` | `VERIFIED` |
| `VERIFIED` | `COMPENSATING`, `COMPENSATED` |
| `COMPENSATING` | `COMPENSATED`, `FAILED` |
| `FAILED`, `REVOKED`, `EXPIRED`, `COMPENSATED` | *(terminal — no outgoing transitions)* |

Every non-terminal state can reach a terminal state
(`tests/property/test_state_machine_properties.py` checks this via BFS
over the graph, so a future edit that accidentally strands a state is
caught automatically).

## Safe checkpoints for revocation

`REVOCABLE_STATES = {PROPOSED, PREPARED, SEALED, AUTHORIZED}` — i.e.
anything **before** `COMMITTING`. Once a manifest has entered `COMMITTING`,
revocation can no longer stop it (invariant #27): the external adapter
call may already be in flight, and there is no safe way to interrupt an
external side effect mid-call. `engine.revoke()` still marks the grant
revoked in the store (so it can never be used again), but only reports
`stopped_at_safepoint=True` if the lifecycle record was still in a
revocable state; otherwise it reports `False` and the already-committed
effect stands (invariant #26 — revocation cannot undo a completed
irreversible effect).

## Why the engine tracks state in memory, not the database

`LifecycleRecord` lives in `KarmaSakshiEngine._records`, keyed by
`manifest_id`. The audit journal is the durable source of truth for *what
happened*; the in-memory record exists purely to make the *next*
transition attempt fail fast and consistently within one engine instance's
lifetime. A host that creates a fresh engine per request (the CLI is the
extreme case) reconstructs the correct starting state by replaying the
audit journal — see
`Workspace.reconstruct_lifecycle_state()` and
`engine.seed_lifecycle_state()` — before calling the next lifecycle
method. This is a deliberate simplicity/durability tradeoff: it avoids a
second persisted-state table that would need to stay in lockstep with the
audit log's own record of transitions.
