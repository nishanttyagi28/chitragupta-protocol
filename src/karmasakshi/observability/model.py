"""Neutral, versioned lifecycle observability events (extreme-v2 Phase 24).

This is **not** an integration with any named observability product -- no
OpenTelemetry, Datadog, Honeycomb, or Prometheus client is used or
implied. It defines one stable, documented JSON event shape a real
exporter could sit on top of later, mirroring the same honest boundary as
the AgentEval regression-fixture export
(docs/agenteval-integration.md): a self-describing, versioned document,
not a claim of compatibility with any specific upstream schema.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.config.clock import ensure_utc
from karmasakshi.errors import SchemaVersionError

OBSERVABILITY_EVENT_SCHEMA_VERSION = "1.0"


class ObservabilityEventType(str, Enum):
    """Lifecycle points the reference CLI/API emit by default. Closed
    (not freely extensible), matching the versioned, self-describing
    contract of :class:`ObservabilityEvent`."""

    MANIFEST_PREPARED = "manifest.prepared"
    GRANT_AUTHORIZED = "grant.authorized"
    EFFECT_COMMITTED = "effect.committed"
    EFFECT_VERIFIED = "effect.verified"
    EFFECT_COMPENSATED = "effect.compensated"
    LIFECYCLE_FAILED = "lifecycle.failed"


class ObservabilityEvent(BaseModel):
    """One neutral, structured lifecycle observation. Never carries secrets
    or raw credentials -- only identifiers and classification already
    present in the audit trail."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = OBSERVABILITY_EVENT_SCHEMA_VERSION
    event_type: ObservabilityEventType
    emitted_at: datetime
    manifest_id: str
    manifest_hash: str | None = None
    grant_id: str | None = None
    lifecycle_state: str | None = None
    decision: str | None = None
    tenant_id: str | None = None
    detail: str | None = None

    @field_validator("schema_version")
    @classmethod
    def _validate_schema(cls, v: str) -> str:
        if v != OBSERVABILITY_EVENT_SCHEMA_VERSION:
            raise SchemaVersionError(
                f"ObservabilityEvent requires schema_version "
                f"{OBSERVABILITY_EVENT_SCHEMA_VERSION!r}, got {v!r}"
            )
        return v

    @field_validator("manifest_id")
    @classmethod
    def _validate_manifest_id(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("manifest_id must be 1-256 chars")
        return v

    @field_validator("detail")
    @classmethod
    def _validate_detail(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 2048:
            raise ValueError("detail must be at most 2048 chars")
        return v

    @field_validator("emitted_at")
    @classmethod
    def _validate_emitted_at(cls, v: datetime) -> datetime:
        return ensure_utc(v)


__all__ = [
    "OBSERVABILITY_EVENT_SCHEMA_VERSION",
    "ObservabilityEvent",
    "ObservabilityEventType",
]
