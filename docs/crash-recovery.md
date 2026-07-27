# Crash Recovery

## The problem

A process can crash at any point. The dangerous window is: *after* an
adapter's external effect has actually happened (money moved, email sent,
row updated) but *before* the local grant store has finalized the
reservation. On restart, naively retrying would risk double-executing a
consequential action — exactly what invariant #19 (idempotent retries) and
#20 (a successful response is not proof) exist to prevent.

## The two recovery paths

### 1. Idempotent replay (the common case)

Every commit finalizes with
`grant_store.commit(grant_id, manifest.idempotency_key, outcome_ref)`,
which records `idempotency_key -> outcome_ref` in the store's idempotency
ledger. If a *new* manifest is prepared for the same real-world intent
(same `idempotency_key`, different `manifest_id`/`nonce` — e.g. a client
retrying the whole propose→commit pipeline after a timeout) and reaches
`engine.commit()`, the engine checks
`grant_store.get_idempotent_outcome(manifest.idempotency_key)` **before**
calling the adapter. If found, it finalizes the new grant's reservation
against the *existing* outcome and returns immediately — the adapter is
never called a second time. This is exercised by
`test_idempotent_retry_does_not_recommit` and demonstrated live in
`chitragupta demo --all`.

This path only helps if the *first* attempt's `grant_store.commit()` call
actually completed. If the crash happened between the adapter's effect
succeeding and that store write, the ledger was never populated — the
ambiguous case below.

### 2. Ambiguous-outcome recovery (the crash-mid-commit case)

`engine.recover_ambiguous_commit(manifest, adapter, context)`:

- Never performs the external effect itself.
- Calls `adapter.verify()` with a synthetic probe `CommitResult(success=True,
  provider_reference=None, ...)` — a signal to the adapter to independently
  re-observe its own external system of record by `idempotency_key`,
  rather than trusting any commit result.
- If the adapter finds evidence (`matched_expected=True`), the engine
  backfills the idempotency ledger via
  `grant_store.record_idempotent_outcome()` so a subsequent `commit()`
  call takes the fast idempotent-replay path instead of re-invoking the
  adapter.
- If no evidence is found, nothing is backfilled — the caller should
  proceed with a normal, fresh `engine.commit()`.

**Callers must call this (or otherwise independently confirm external
state) before retrying an ambiguous commit. Never retry blindly.**

## The payment simulator's ambiguous-timeout mode

`PaymentSimulator.inject_ambiguous_timeout()` makes the *next*
`submit_payment()` call settle the payment in the provider's own ledger
and then raise `TimeoutError` to the caller — modeling exactly "the
request succeeded server-side, but the client never learned that." The
adapter's `commit()` catches this and returns
`CommitResult(success=False, detail="ambiguous: ...")` rather than letting
a raw exception propagate, and its `verify()` always re-queries the
simulator by `idempotency_key`, never trusting `commit_result`. See
`test_ambiguous_timeout_settles_but_reports_failure` and demo scenario 12.

## What is not implemented

There is no automated background reconciliation job that scans for
ambiguous outcomes and calls `recover_ambiguous_commit()` proactively —
that is left to the calling application (or the CLI/API operator), since
what counts as "safe to auto-retry" is domain-specific.
