"""Engine dependencies, bundled so callers construct them once and reuse."""

from __future__ import annotations

from dataclasses import dataclass, field

from chitragupta.audit.journal import AuditJournal
from chitragupta.config.clock import SYSTEM_CLOCK, Clock
from chitragupta.config.settings import ClockSkewPolicy
from chitragupta.crypto.keyring import Keyring
from chitragupta.stores.base import GrantStore


@dataclass
class EngineContext:
    keyring: Keyring
    grant_store: GrantStore
    audit: AuditJournal
    clock: Clock = SYSTEM_CLOCK
    clock_skew: ClockSkewPolicy = field(default_factory=ClockSkewPolicy)


__all__ = ["EngineContext"]
