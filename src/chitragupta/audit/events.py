"""Audit event schema.

Every consequential decision the engine makes -- legal or illegal
transition, grant issuance, commit attempt, verification, compensation --
produces one :class:`AuditEvent`. Events never carry secrets or raw
credentials; only redacted metadata (see docs/security-model.md).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from chitragupta.config.clock import ensure_utc


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int
    event_id: str
    previous_hash: str | None
    event_hash: str = ""  # populated by the journal after previous_hash is known
    timestamp: datetime
    manifest_id: str | None = None
    manifest_hash: str | None = None
    grant_id: str | None = None
    actor_id: str | None = None
    event_type: str
    from_state: str | None = None
    to_state: str | None = None
    decision: str
    metadata: dict[str, str] = {}

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @field_validator("sequence")
    @classmethod
    def _validate_sequence(cls, v: int) -> int:
        if v < 1:
            raise ValueError("sequence must be >= 1")
        return v

    @field_validator("event_id", "event_type", "decision")
    @classmethod
    def _validate_nonempty(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("must be 1-256 chars")
        return v

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 32:
            raise ValueError("audit event metadata: at most 32 keys permitted")
        for key, value in v.items():
            if len(key) > 64 or len(value) > 1024:
                raise ValueError(f"audit event metadata entry {key!r} exceeds size limits")
        return v

    @classmethod
    def new_event_id(cls) -> str:
        return str(uuid.uuid4())


__all__ = ["AuditEvent"]
