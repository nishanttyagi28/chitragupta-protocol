"""Engine dependencies, bundled so callers construct them once and reuse."""

from __future__ import annotations

from dataclasses import dataclass, field

from karmasakshi.audit.journal import AuditJournal
from karmasakshi.budget.ledger import BudgetLedger
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.config.settings import ClockSkewPolicy
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.intelligence.engine import EffectIntelligenceEngine
from karmasakshi.outbox.model import OutboxStore
from karmasakshi.stores.base import GrantStore
from karmasakshi.stores.lifecycle import LifecycleStore


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
    #: Optional Phase 13 durable lifecycle store. When set, successful
    #: transitions and ``seed_lifecycle_state`` write through; reads hydrate
    #: the in-process record. When ``None``, lifecycle remains process-local
    #: (v0.1 / Phases 1-12 behavior).
    lifecycle_store: LifecycleStore | None = None
    #: Optional Phase 15 transactional outbox for durable commit intent.
    #: When set, ``commit()`` records PENDING before the adapter runs.
    outbox_store: OutboxStore | None = None


__all__ = ["EngineContext"]
