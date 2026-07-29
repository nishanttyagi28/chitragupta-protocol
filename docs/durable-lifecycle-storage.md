# Durable Lifecycle Storage (extreme-v2 Phase 13)

The audit journal remains the tamper-evident record of every allowed
(and blocked) lifecycle transition. Phase 13 adds an optional
**LifecycleStore** so a restarted host can know the current state without
relying only on audit replay.

## Surfaces

- ``LifecycleStore`` protocol: ``get`` / ``set`` / ``compare_and_set``
- ``InMemoryLifecycleStore`` — process-local
- ``SQLiteLifecycleStore`` — single-node durable ``lifecycle.db``
- ``EngineContext.lifecycle_store`` — optional; ``None`` keeps Phases 1–12
  process-local ``_records`` behavior
- CLI workspace and API default state open ``lifecycle.db`` alongside
  grants/audit

## Engine behavior

- Successful ``_transition`` write-through via ``compare_and_set``
- Store failure rolls back the in-memory advance and raises
  ``StoreUnavailableError`` (fail closed)
- ``_get_record`` hydrates from the store when memory is empty
- ``seed_lifecycle_state`` / CLI ``reconstruct_lifecycle_state`` prefer
  the store, with audit last-``to_state`` as a migration fallback

## Honesty limits

- SQLite lifecycle is **single-node** (same semantics as the grant SQLite
  store). Not multi-machine consensus.
- Saga run durability, budget ledgers, and witness stores remain separate
  follow-ons.
- The audit hash chain is not replaced by the lifecycle store.
