"""Engine dependencies, bundled so callers construct them once and reuse."""

from __future__ import annotations

from dataclasses import dataclass, field

from karmasakshi.audit.journal import AuditJournal
from karmasakshi.budget.ledger import BudgetLedger
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.config.settings import ClockSkewPolicy
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.intelligence.engine import EffectIntelligenceEngine
from karmasakshi.stores.base import GrantStore


@dataclass
class EngineContext:
    keyring: Keyring
    grant_store: GrantStore
    audit: AuditJournal
    clock: Clock = SYSTEM_CLOCK
    clock_skew: ClockSkewPolicy = field(default_factory=ClockSkewPolicy)
    intelligence: EffectIntelligenceEngine = field(default_factory=EffectIntelligenceEngine)
    #: Optional Phase 12 authority-budget ledger. Required when any grant
    #: carries ``authority_budget_id``; omitted otherwise (additive).
    budget_ledger: BudgetLedger | None = None


__all__ = ["EngineContext"]
