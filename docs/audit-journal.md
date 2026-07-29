# Audit Journal Abstraction (extreme-v2 Phase 14)

The hash-chained :class:`~karmasakshi.audit.journal.AuditJournal` is the
tamper-evident record of protocol decisions (invariants #22–#23). Phase 14
clarifies the pluggable backend contract and adds an optional Redis sink
for shared append across processes — without inventing consensus.

## `AuditBackend` protocol

```text
append(event) -> None          # durable accept or raise; never silent drop
all_events() -> list[AuditEvent]
last_event() -> AuditEvent | None
```

Implementations:

| Backend | Scope | Multi-writer |
|---|---|---|
| `InMemoryAuditBackend` | Process-local | Thread lock in journal |
| `SQLiteAuditBackend` | Single-node file | PK on `sequence`; conflict → `AuditWriteError` |
| `RedisAuditBackend` | Shared Redis | Lua: `LLEN+1 == sequence` then `RPUSH`; conflict → `AuditWriteError` |

## Honesty limits

- Redis Lua atomicity is **not** Raft, etcd, or multi-DC consensus.
- The journal's `threading.Lock` is **process-local**; cross-process safety
  comes only from the backend's conflict rejection.
- Default CLI/API still use SQLite. Redis audit is opt-in for deployers
  that already run Redis for grants.
