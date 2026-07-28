"""In-process lifecycle tracking for a single manifest.

This complements (does not replace) the durable audit journal: the audit
journal is the tamper-evident record of what happened, while a
:class:`LifecycleRecord` is a lightweight, mutable convenience object the
engine uses to enforce legal transitions before it ever asks the audit
journal to persist anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from chitragupta.state_machine.states import LifecycleState, assert_legal_transition


@dataclass
class LifecycleRecord:
    manifest_id: str
    state: LifecycleState = LifecycleState.PROPOSED
    history: list[tuple[LifecycleState, LifecycleState, datetime]] = field(default_factory=list)

    def transition(self, target: LifecycleState, at: datetime) -> None:
        assert_legal_transition(self.state, target)
        self.history.append((self.state, target, at))
        self.state = target


__all__ = ["LifecycleRecord"]
