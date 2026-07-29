"""Transactional outbox for commit intent (extreme-v2 Phase 15).

Records that a commit was *attempted* so crash recovery can distinguish
pending intent from verified completion. Does **not** claim exactly-once
execution — only durable intent + fail-closed recovery.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.config.clock import ensure_utc
from karmasakshi.protocol.versioning import CURRENT_SCHEMA_VERSION, assert_supported_schema_version

OutboxStatus = Literal["pending", "confirmed", "abandoned"]


class OutboxEntry(BaseModel):
    """One durable commit-intent row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    idempotency_key: str
    grant_id: str
    manifest_id: str
    manifest_hash: str
    status: OutboxStatus
    created_at: datetime
    outcome_ref: str | None = None

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, v: str) -> str:
        assert_supported_schema_version(v)
        return v

    @field_validator("created_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return ensure_utc(v)


@runtime_checkable
class OutboxStore(Protocol):
    def record_pending(self, entry: OutboxEntry) -> None:
        """Insert a pending intent. Fails closed if the key already exists
        with a different identity (grant/manifest)."""
        ...

    def get(self, idempotency_key: str) -> OutboxEntry | None: ...

    def mark_confirmed(self, idempotency_key: str, outcome_ref: str) -> None: ...

    def mark_abandoned(self, idempotency_key: str) -> None: ...

    def list_pending(self) -> list[OutboxEntry]: ...


__all__ = ["OutboxEntry", "OutboxStatus", "OutboxStore"]
