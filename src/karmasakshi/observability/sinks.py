"""Pluggable observability sinks: where lifecycle events go.

Sinks are best-effort and never security-critical: a failing, slow, or
buggy sink must never block, fail, or alter the outcome of a lifecycle
call. :func:`emit_safely` -- the only way the engine sends an event to a
sink -- swallows every sink exception and logs it instead of propagating,
the same "advisory only" posture already established for the Effect
Intelligence Engine (Phase 1) and the AgentEval regression export. See
docs/observability.md.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Protocol, runtime_checkable

from karmasakshi.observability.model import ObservabilityEvent

_logger = logging.getLogger("karmasakshi.observability")


@runtime_checkable
class ObservabilitySink(Protocol):
    def emit(self, event: ObservabilityEvent) -> None: ...


class NullObservabilitySink:
    """Discards every event. The implicit default when no sink is configured."""

    def emit(self, event: ObservabilityEvent) -> None:
        return None


class InMemoryObservabilitySink:
    """Collects events in process memory -- for tests and local inspection,
    not a durable store."""

    def __init__(self) -> None:
        self._events: list[ObservabilityEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: ObservabilityEvent) -> None:
        with self._lock:
            self._events.append(event)

    def events(self) -> list[ObservabilityEvent]:
        with self._lock:
            return list(self._events)


class JsonlObservabilitySink:
    """Appends one JSON object per line to a local file: a portable,
    tail-able, grep-able format any real log shipper could pick up. This
    is not a claim of integration with any specific log-shipping product
    -- it is a documented, stable boundary, same as
    :mod:`karmasakshi.integrations.agenteval.export`.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    def emit(self, event: ObservabilityEvent) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(event.model_dump_json() + "\n")


def emit_safely(sink: ObservabilitySink | None, event: ObservabilityEvent) -> None:
    """Send ``event`` to ``sink`` if configured; never raise.

    Observability is advisory: a broken sink (disk full, a bug in a
    caller-supplied sink, a future remote sink with a network outage) must
    never affect the security-critical lifecycle result it is describing.
    Failures are logged, not propagated.
    """
    if sink is None:
        return
    try:
        sink.emit(event)
    except Exception:
        _logger.warning(
            "observability sink %r raised while emitting %s for manifest %s",
            type(sink).__name__,
            event.event_type.value,
            event.manifest_id,
            exc_info=True,
        )


__all__ = [
    "InMemoryObservabilitySink",
    "JsonlObservabilitySink",
    "NullObservabilitySink",
    "ObservabilitySink",
    "emit_safely",
]
