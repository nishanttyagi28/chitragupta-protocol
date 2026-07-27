"""In-memory grant store.

Suitable for unit tests and local examples only -- state is process-local
and lost on restart. Thread-safe via a single lock guarding all mutations,
which is sufficient to prove single-use/at-most-once-commit invariants
under concurrent threads within one process (see
tests/property and tests/unit/test_stores_memory.py for concurrency proofs).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass
class _Slot:
    max_uses: int
    uses: int = 0
    revoked: bool = False
    reserved: bool = False


class InMemoryGrantStore:
    def __init__(self) -> None:
        self._slots: dict[str, _Slot] = {}
        self._idempotency: dict[str, str] = {}
        self._lock = threading.Lock()

    def reserve(self, grant_id: str, max_uses: int) -> bool:
        with self._lock:
            slot = self._slots.get(grant_id)
            if slot is None:
                slot = _Slot(max_uses=max_uses)
                self._slots[grant_id] = slot
            if slot.revoked or slot.reserved or slot.uses >= slot.max_uses:
                return False
            slot.reserved = True
            return True

    def release(self, grant_id: str) -> None:
        with self._lock:
            slot = self._slots.get(grant_id)
            if slot is not None:
                slot.reserved = False

    def commit(self, grant_id: str, idempotency_key: str, outcome_ref: str) -> None:
        with self._lock:
            slot = self._slots.get(grant_id)
            if slot is None or not slot.reserved:
                raise RuntimeError(
                    f"commit() called for grant {grant_id!r} without a held reservation"
                )
            slot.uses += 1
            slot.reserved = False
            self._idempotency[idempotency_key] = outcome_ref

    def revoke(self, grant_id: str) -> None:
        with self._lock:
            slot = self._slots.get(grant_id)
            if slot is None:
                slot = _Slot(max_uses=0)
                self._slots[grant_id] = slot
            slot.revoked = True

    def is_revoked(self, grant_id: str) -> bool:
        with self._lock:
            slot = self._slots.get(grant_id)
            return slot.revoked if slot is not None else False

    def get_use_count(self, grant_id: str) -> int:
        with self._lock:
            slot = self._slots.get(grant_id)
            return slot.uses if slot is not None else 0

    def get_idempotent_outcome(self, idempotency_key: str) -> str | None:
        with self._lock:
            return self._idempotency.get(idempotency_key)


__all__ = ["InMemoryGrantStore"]
