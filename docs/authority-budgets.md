# Atomic Authority Budgets (extreme-v2 Phase 12)

Consumable authority budgets are **shared ledgers** of remaining capacity —
distinct from per-grant ``ScopeConstraints.max_amount`` attenuation caps.

A grant may optionally bind ``authority_budget_id``. At ``commit()``, the
engine atomically reserves and (on success) consumes from that budget
before the adapter effect runs. Exhaustion fails closed.

## Kinds

| Kind | Consume amount | Requirements |
|---|---|---|
| ``monetary`` | ``manifest.estimated_cost.minor_units`` | Matching 3-letter currency; missing/mismatched cost fails closed |
| ``count`` | ``1`` per successful commit | — |

## Surfaces

- ``karmasakshi.budget.AuthorityBudget`` — versioned, hashable definition
- ``karmasakshi.budget.InMemoryBudgetLedger`` — thread-safe single-process
  reserve / release / commit / consume
- ``EngineContext.budget_ledger`` — optional; required when any grant binds
  a budget id
- ``ExecutionGrant.authority_budget_id`` — signed binding
- ``engine.authorize(..., authority_budget_id=...)`` and sibling authorize
  paths; ``delegate`` inherits the parent's budget by default

## Invariants

- **#60** A grant bound to an authority budget cannot commit when remaining
  capacity is insufficient (exhaustion fails closed).
- **#61** Budget consumption is atomic under the ledger lock; concurrent
  reserves cannot oversubscribe a single-process ledger.
- **#62** Dropping or swapping a parent ``authority_budget_id`` on
  delegation is treated as widening and rejected.
- **#63** Binding a budget without a configured ledger, or to an unknown
  budget id, fails closed at authorize/commit.

## Honesty limits

- ``InMemoryBudgetLedger`` is **single-process only**. Multi-node durable
  budget ledgers are deferred to Phase 13+ storage work — never claim
  cross-process exactly-once budget accounting from this implementation.
- Failed adapter commits release the reservation (capacity returns).
- Idempotent replay of an already-committed effect releases a fresh
  reservation without consuming again.
- Budgets do not replace ``scope.max_amount``; both may apply.
