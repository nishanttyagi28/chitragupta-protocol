"""Resolve how much of an authority budget a commit consumes."""

from __future__ import annotations

from karmasakshi.budget.ledger import BudgetLedger
from karmasakshi.budget.model import AuthorityBudget
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.errors import AuthorityBudgetError


def resolve_budget_consume_amount(budget: AuthorityBudget, manifest: EffectManifest) -> int:
    """Deterministic consume amount for one commit against ``budget``.

    - ``count`` budgets consume exactly ``1`` per successful commit.
    - ``monetary`` budgets consume ``manifest.estimated_cost.minor_units``
      and require a matching currency; missing or mismatched cost fails
      closed (never invent an amount).
    """
    if budget.kind == "count":
        return 1
    cost = manifest.estimated_cost
    if cost is None:
        raise AuthorityBudgetError(
            f"monetary authority budget {budget.budget_id} requires "
            "manifest.estimated_cost; refuse to invent a consume amount"
        )
    if budget.currency is None or cost.currency != budget.currency:
        raise AuthorityBudgetError(
            f"manifest estimated_cost currency {cost.currency!r} does not match "
            f"authority budget {budget.budget_id} currency {budget.currency!r}"
        )
    if cost.minor_units < 1:
        raise AuthorityBudgetError(
            "monetary authority budget consume requires estimated_cost.minor_units >= 1"
        )
    return cost.minor_units


def require_budget(ledger: BudgetLedger | None, budget_id: str) -> AuthorityBudget:
    """Fail closed if no ledger is configured or the budget is unknown."""
    if ledger is None:
        raise AuthorityBudgetError(
            f"grant binds authority_budget_id={budget_id!r} but EngineContext "
            "has no budget_ledger; refuse to authorize/commit without a ledger"
        )
    return ledger.get(budget_id)


__all__ = ["require_budget", "resolve_budget_consume_amount"]
