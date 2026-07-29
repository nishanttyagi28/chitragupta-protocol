"""Atomic authority budgets (extreme-v2 Phase 12).

Consumable budgets distinct from per-grant ``ScopeConstraints.max_amount``
caps. A budget can be shared across grants; consumption is atomic and
fail-closed on exhaustion or store uncertainty.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.errors import AuthorityBudgetError
from karmasakshi.protocol.versioning import CURRENT_SCHEMA_VERSION, assert_supported_schema_version


class AuthorityBudget(BaseModel):
    """A versioned, hashable budget definition (limits only; consumption
    lives in the budget ledger)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    budget_id: str
    kind: Literal["monetary", "count"]
    currency: str | None = None
    limit_minor_units: int | None = None
    limit_count: int | None = None

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, v: str) -> str:
        assert_supported_schema_version(v)
        return v

    @field_validator("budget_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("budget_id must be 1-128 chars")
        return v

    @model_validator(mode="after")
    def _shape(self) -> AuthorityBudget:
        if self.kind == "monetary":
            if not self.currency or len(self.currency) != 3:
                raise ValueError("monetary budgets require a 3-letter currency")
            if self.limit_minor_units is None or self.limit_minor_units < 1:
                raise ValueError("monetary budgets require limit_minor_units >= 1")
            if self.limit_count is not None:
                raise ValueError("monetary budgets must not set limit_count")
        else:
            if self.limit_count is None or self.limit_count < 1:
                raise ValueError("count budgets require limit_count >= 1")
            if self.limit_minor_units is not None or self.currency is not None:
                raise ValueError("count budgets must not set monetary fields")
        return self

    def limit(self) -> int:
        if self.kind == "monetary":
            if self.limit_minor_units is None:
                raise AuthorityBudgetError("monetary budget missing limit_minor_units")
            return self.limit_minor_units
        if self.limit_count is None:
            raise AuthorityBudgetError("count budget missing limit_count")
        return self.limit_count

    def canonical_hash(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))


__all__ = ["AuthorityBudget"]
