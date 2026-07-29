"""Atomic authority budgets (Phase 12)."""

from __future__ import annotations

from karmasakshi.budget.consume import require_budget, resolve_budget_consume_amount
from karmasakshi.budget.ledger import BudgetLedger, InMemoryBudgetLedger
from karmasakshi.budget.model import AuthorityBudget

__all__ = [
    "AuthorityBudget",
    "BudgetLedger",
    "InMemoryBudgetLedger",
    "require_budget",
    "resolve_budget_consume_amount",
]
