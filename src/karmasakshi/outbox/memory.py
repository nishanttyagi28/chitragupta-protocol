"""In-process transactional outbox (Phase 15)."""

from __future__ import annotations

import threading

from karmasakshi.errors import KarmaSakshiError
from karmasakshi.outbox.model import OutboxEntry


class OutboxConflictError(KarmaSakshiError):
    """Outbox key already bound to a different intent or illegal status change."""


class InMemoryOutboxStore:
    def __init__(self) -> None:
        self._entries: dict[str, OutboxEntry] = {}
        self._lock = threading.Lock()

    def record_pending(self, entry: OutboxEntry) -> None:
        if entry.status != "pending":
            raise OutboxConflictError("record_pending requires status=pending")
        with self._lock:
            existing = self._entries.get(entry.idempotency_key)
            if existing is not None:
                if (
                    existing.grant_id != entry.grant_id
                    or existing.manifest_hash != entry.manifest_hash
                ):
                    raise OutboxConflictError(
                        f"outbox key {entry.idempotency_key!r} already bound to a "
                        "different grant/manifest"
                    )
                if existing.status != "pending":
                    raise OutboxConflictError(
                        f"outbox key {entry.idempotency_key!r} already {existing.status}"
                    )
                return
            self._entries[entry.idempotency_key] = entry

    def get(self, idempotency_key: str) -> OutboxEntry | None:
        with self._lock:
            return self._entries.get(idempotency_key)

    def mark_confirmed(self, idempotency_key: str, outcome_ref: str) -> None:
        with self._lock:
            entry = self._require(idempotency_key)
            if entry.status == "confirmed":
                return
            if entry.status != "pending":
                raise OutboxConflictError(
                    f"cannot confirm outbox key {idempotency_key!r} in status {entry.status}"
                )
            self._entries[idempotency_key] = entry.model_copy(
                update={"status": "confirmed", "outcome_ref": outcome_ref}
            )

    def mark_abandoned(self, idempotency_key: str) -> None:
        with self._lock:
            entry = self._require(idempotency_key)
            if entry.status == "abandoned":
                return
            if entry.status != "pending":
                raise OutboxConflictError(
                    f"cannot abandon outbox key {idempotency_key!r} in status {entry.status}"
                )
            self._entries[idempotency_key] = entry.model_copy(update={"status": "abandoned"})

    def list_pending(self) -> list[OutboxEntry]:
        with self._lock:
            return [e for e in self._entries.values() if e.status == "pending"]

    def _require(self, idempotency_key: str) -> OutboxEntry:
        entry = self._entries.get(idempotency_key)
        if entry is None:
            raise OutboxConflictError(f"unknown outbox key {idempotency_key!r}")
        return entry


__all__ = ["InMemoryOutboxStore", "OutboxConflictError"]
