"""Append-only, tamper-evident audit journal.

Each event's hash binds its own content plus the previous event's hash,
forming a chain: mutating or deleting any past event breaks every
subsequent hash, which :meth:`AuditJournal.verify_chain` detects
deterministically (invariant #22).

Backends implement :class:`~karmasakshi.audit.base.AuditBackend`. The
in-memory backend is the default; SQLite and Redis (optional) backends
plug in via the same protocol. See docs/audit-journal.md.
"""

from __future__ import annotations

import threading

from karmasakshi.audit.base import AuditBackend
from karmasakshi.audit.events import AuditEvent
from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.errors import AuditTamperedError, AuditWriteError


class InMemoryAuditBackend:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event)

    def all_events(self) -> list[AuditEvent]:
        return list(self._events)

    def last_event(self) -> AuditEvent | None:
        return self._events[-1] if self._events else None


def _event_hash(event: AuditEvent) -> str:
    return canonical_hash(event.model_dump(mode="json", exclude={"event_hash"}))


class AuditJournal:
    """Thread-safe wrapper that maintains the hash chain over a backend.

    The process-local lock serializes callers in one process. Cross-process
    safety requires a backend that rejects conflicting appends (SQLite
    primary-key / Redis Lua sequence check). The journal lock alone is
    not a distributed lock.
    """

    def __init__(self, backend: AuditBackend | None = None, clock: Clock = SYSTEM_CLOCK) -> None:
        self._backend = backend or InMemoryAuditBackend()
        self._clock = clock
        self._lock = threading.Lock()

    def record(
        self,
        *,
        event_type: str,
        decision: str,
        manifest_id: str | None = None,
        manifest_hash: str | None = None,
        grant_id: str | None = None,
        actor_id: str | None = None,
        from_state: str | None = None,
        to_state: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> AuditEvent:
        with self._lock:
            previous = self._backend.last_event()
            sequence = (previous.sequence + 1) if previous else 1
            previous_hash = previous.event_hash if previous else None
            event = AuditEvent(
                sequence=sequence,
                event_id=AuditEvent.new_event_id(),
                previous_hash=previous_hash,
                timestamp=self._clock.now(),
                manifest_id=manifest_id,
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                event_type=event_type,
                from_state=from_state,
                to_state=to_state,
                decision=decision,
                metadata=metadata or {},
            )
            event = event.model_copy(update={"event_hash": _event_hash(event)})
            try:
                self._backend.append(event)
            except AuditWriteError:
                raise
            except Exception as exc:
                raise AuditWriteError(
                    f"failed to durably write audit event {event.event_id}"
                ) from exc
            return event

    def all_events(self) -> list[AuditEvent]:
        return self._backend.all_events()

    def events_for_manifest(self, manifest_id: str) -> list[AuditEvent]:
        return [e for e in self.all_events() if e.manifest_id == manifest_id]

    def verify_chain(self) -> None:
        expected_previous_hash: str | None = None
        expected_sequence = 1
        for event in self.all_events():
            if event.sequence != expected_sequence:
                raise AuditTamperedError(
                    f"audit chain sequence gap: expected {expected_sequence}, got {event.sequence}"
                )
            if event.previous_hash != expected_previous_hash:
                raise AuditTamperedError(
                    f"audit chain broken at sequence {event.sequence}: previous_hash mismatch"
                )
            recomputed = _event_hash(event)
            if recomputed != event.event_hash:
                raise AuditTamperedError(
                    f"audit event {event.event_id} (sequence {event.sequence}) was tampered with: "
                    f"recomputed hash does not match stored hash"
                )
            expected_previous_hash = event.event_hash
            expected_sequence += 1


__all__ = ["AuditBackend", "AuditJournal", "InMemoryAuditBackend"]
