"""Neutral, versioned lifecycle observability (extreme-v2 Phase 24).

See docs/observability.md.
"""

from __future__ import annotations

from karmasakshi.observability.model import (
    OBSERVABILITY_EVENT_SCHEMA_VERSION,
    ObservabilityEvent,
    ObservabilityEventType,
)
from karmasakshi.observability.sinks import (
    InMemoryObservabilitySink,
    JsonlObservabilitySink,
    NullObservabilitySink,
    ObservabilitySink,
    emit_safely,
)

__all__ = [
    "OBSERVABILITY_EVENT_SCHEMA_VERSION",
    "InMemoryObservabilitySink",
    "JsonlObservabilitySink",
    "NullObservabilitySink",
    "ObservabilityEvent",
    "ObservabilityEventType",
    "ObservabilitySink",
    "emit_safely",
]
