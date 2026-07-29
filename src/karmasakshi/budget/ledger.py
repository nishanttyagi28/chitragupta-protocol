"""In-process atomic budget ledger (Phase 12).

Suitable for tests and single-process evaluation. Durable multi-node
budget ledgers are deferred (Phase 13+ storage) — never claim
cross-process atomicity from this implementation.
"""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from karmasakshi.budget.model import AuthorityBudget
from karmasakshi.errors import AuthorityBudgetError, AuthorityBudgetExhaustedError


@runtime_checkable
class BudgetLedger(Protocol):
    """Minimal ledger surface used by the engine."""

    def register(self, budget: AuthorityBudget) -> None: ...

    def get(self, budget_id: str) -> AuthorityBudget: ...

    def remaining(self, budget_id: str) -> int: ...

    def reserve(self, budget_id: str, amount: int) -> bool: ...

    def release(self, budget_id: str, amount: int) -> None: ...

    def commit(self, budget_id: str, amount: int) -> None: ...


class InMemoryBudgetLedger:
    """Thread-safe budget consumption ledger (single process)."""

    def __init__(self) -> None:
        self._budgets: dict[str, AuthorityBudget] = {}
        self._consumed: dict[str, int] = {}
        self._reserved: dict[str, int] = {}
        self._lock = threading.Lock()

    def register(self, budget: AuthorityBudget) -> None:
        with self._lock:
            existing = self._budgets.get(budget.budget_id)
            if existing is not None and existing.canonical_hash() != budget.canonical_hash():
                raise AuthorityBudgetError(
                    f"budget {budget.budget_id} already registered with a different definition"
                )
            self._budgets[budget.budget_id] = budget
            self._consumed.setdefault(budget.budget_id, 0)
            self._reserved.setdefault(budget.budget_id, 0)

    def get(self, budget_id: str) -> AuthorityBudget:
        with self._lock:
            return self._require(budget_id)

    def remaining(self, budget_id: str) -> int:
        with self._lock:
            budget = self._require(budget_id)
            return budget.limit() - self._consumed[budget_id] - self._reserved[budget_id]

    def reserve(self, budget_id: str, amount: int) -> bool:
        if amount < 1:
            raise AuthorityBudgetError("budget reserve amount must be >= 1")
        with self._lock:
            budget = self._require(budget_id)
            available = budget.limit() - self._consumed[budget_id] - self._reserved[budget_id]
            if amount > available:
                return False
            self._reserved[budget_id] += amount
            return True

    def release(self, budget_id: str, amount: int) -> None:
        with self._lock:
            self._require(budget_id)
            if amount < 1 or amount > self._reserved[budget_id]:
                raise AuthorityBudgetError(
                    f"cannot release {amount} from budget {budget_id} "
                    f"(reserved={self._reserved[budget_id]})"
                )
            self._reserved[budget_id] -= amount

    def commit(self, budget_id: str, amount: int) -> None:
        """Finalize a prior reservation into consumed capacity."""
        with self._lock:
            self._require(budget_id)
            if amount < 1 or amount > self._reserved[budget_id]:
                raise AuthorityBudgetError(
                    f"cannot commit {amount} on budget {budget_id} "
                    f"(reserved={self._reserved[budget_id]})"
                )
            self._reserved[budget_id] -= amount
            self._consumed[budget_id] += amount

    def consume(self, budget_id: str, amount: int) -> None:
        """Atomically reserve+commit ``amount`` in one critical section."""
        if amount < 1:
            raise AuthorityBudgetError("budget consume amount must be >= 1")
        with self._lock:
            budget = self._require(budget_id)
            available = budget.limit() - self._consumed[budget_id] - self._reserved[budget_id]
            if amount > available:
                raise AuthorityBudgetExhaustedError(
                    f"authority budget {budget_id} exhausted for amount={amount} "
                    f"(remaining={available})"
                )
            self._consumed[budget_id] += amount

    def assert_can_reserve(self, budget_id: str, amount: int) -> None:
        """Reserve ``amount`` or raise :class:`AuthorityBudgetExhaustedError`."""
        if not self.reserve(budget_id, amount):
            raise AuthorityBudgetExhaustedError(
                f"authority budget {budget_id} exhausted for amount={amount} "
                f"(remaining={self.remaining(budget_id)})"
            )

    def _require(self, budget_id: str) -> AuthorityBudget:
        budget = self._budgets.get(budget_id)
        if budget is None:
            raise AuthorityBudgetError(f"unknown authority budget {budget_id}")
        return budget


__all__ = ["BudgetLedger", "InMemoryBudgetLedger"]
