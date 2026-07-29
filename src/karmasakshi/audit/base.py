"""Audit backend protocol (extreme-v2 Phase 14).

Backends store ordered events; :class:`~karmasakshi.audit.journal.AuditJournal`
owns the hash chain. A shared backend (e.g. Redis) can be used by multiple
processes — atomicity is whatever the store provides (Lua ``EVAL``), not
Raft/etcd consensus.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from karmasakshi.audit.events import AuditEvent


@runtime_checkable
class AuditBackend(Protocol):
    """Append-only ordered event sink.

    ``append`` must either durably accept the event or raise. Silent drops
    are forbidden. Concurrent appends that lose a race must raise (fail
    closed), never overwrite or reorder prior events.
    """

    def append(self, event: AuditEvent) -> None: ...

    def all_events(self) -> list[AuditEvent]: ...

    def last_event(self) -> AuditEvent | None: ...


__all__ = ["AuditBackend"]
