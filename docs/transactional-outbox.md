# Transactional Outbox and Recovery (extreme-v2 Phase 15)

Durable **commit intent** separate from verified completion. Records that
the engine was about to (or did) invoke the adapter so crash recovery can
fail closed instead of inventing success.

## Status triad

| Status | Meaning |
|---|---|
| `pending` | Intent recorded after grant reserve / `COMMITTING`; adapter may or may not have run |
| `confirmed` | Local store finalized with an outcome ref (commit success or recovery evidence) |
| `abandoned` | Attempt failed before adapter (stale preconditions, etc.) with no ambiguity |

## Engine wiring

1. After `COMMITTING`, before `adapter.commit`, write `pending`
2. On successful local finalize → `confirmed`
3. On clear pre-adapter failure → `abandoned`
4. On adapter exception → leave `pending` (ambiguous); call
   `recover_ambiguous_commit` before retry
5. Recovery with evidence → backfill idempotency ledger + `confirmed`

## Honesty

- **Not** exactly-once. At-most-once successful finalize + explicit ambiguity.
- Single-node SQLite by default (`outbox.db`). No multi-node consensus.
- Never treat pending alone as verified completion.
