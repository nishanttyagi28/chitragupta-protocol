# Storage Semantics

`karmasakshi.stores` defines one protocol (`GrantStore`) with three
implementations. All three implement the same atomic
reserve → release/commit contract; they differ only in durability and
distribution scope.

## The `GrantStore` protocol

```python
reserve(grant_id, max_uses) -> bool   # atomic: True iff this caller now exclusively holds the slot
release(grant_id) -> None             # after a FAILED attempt: returns the slot without consuming a use
commit(grant_id, idempotency_key, outcome_ref) -> None   # after a SUCCESSFUL attempt: permanently consumes one use
revoke(grant_id) -> None
is_revoked(grant_id) -> bool
get_use_count(grant_id) -> int
get_idempotent_outcome(idempotency_key) -> str | None
record_idempotent_outcome(idempotency_key, outcome_ref) -> None   # crash-recovery only, see crash-recovery.md
```

**Design decision:** a *failed* attempt (adapter raised, preconditions
stale, adapter reported failure) calls `release()`, not `commit()` — it
does not consume one of the grant's `max_uses`. A single-use grant means
"may successfully execute at most once," not "may attempt at most once."
This is documented behavior, not an accident — see
`tests/property/test_store_idempotency_properties.py` for the property
that a released slot is available again.

## In-memory backend (`InMemoryGrantStore`)

Process-local, guarded by a single `threading.Lock`. Suitable for unit
tests and single-process local examples only — all state is lost on
process exit and is invisible to other processes.

## SQLite backend (`SQLiteGrantStore`)

Durable for a single node. **This is explicitly not a horizontally
distributed production backend.** Atomicity comes from
`UPDATE grant_slots SET reserved=1 WHERE ... AND reserved=0 AND uses<max_uses`
inside a transaction — a single UPDATE with a WHERE clause is atomic at
the SQLite engine level, and SQLite serializes writers at the file level,
so this is safe across multiple threads *and* multiple processes on the
same machine sharing one database file. It is not safe, and not intended
to be used, across multiple machines.

Verified: durability across store reopen (simulating a process restart),
concurrent-thread reservation (`test_concurrent_reserve_at_most_one_thread_succeeds`),
and fail-closed behavior when the underlying connection dies
(`test_backend_failure_fails_closed_on_every_mutating_method`).

## Redis backend (`RedisGrantStore`)

Distributed atomic consumption across processes/machines sharing one Redis
instance. Atomicity comes from two server-side Lua scripts (`reserve`,
`commit`) — Redis guarantees `EVAL` runs atomically with respect to every
other client, which is what makes this safe across machines, unlike the
SQLite backend.

`redis` is an optional dependency (`pip install karmasakshi-protocol[redis]`).
The test suite (`tests/unit/test_stores_redis.py`) is collected
unconditionally but every test is **skipped with an explicit reason** if
no Redis instance is reachable at `localhost:6379` (or `REDIS_URL`) —
never silently omitted. In the environment this branch was built in, no
local Redis was available, so those tests are documented as skipped, not
fabricated as passing.

## Audit backends

Parallel structure to grant stores. The hash-chain logic lives in
`AuditJournal` and is backend-agnostic; backends only store and return
events in order.

| Backend | Scope |
|---|---|
| `InMemoryAuditBackend` | Process-local (tests / examples) |
| `SQLiteAuditBackend` | Durable single-node (CLI/API default) |
| `RedisAuditBackend` | Shared Redis append (optional extra); Lua sequence check — **not** Raft/etcd |

Multi-writer honesty: the journal process lock is not a distributed lock.
Conflicting appends must fail closed (`AuditWriteError`) via SQLite
primary-key or Redis Lua `LLEN+1 == sequence`. See
[docs/audit-journal.md](audit-journal.md).
