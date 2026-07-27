"""Grant consumption store contract.

The store is what actually enforces exactly-once/at-most-once execution
(invariants #4, #5, #19): ``reserve`` must be atomic so that under
concurrent callers only one can hold the reservation for a given grant at
a time. A failed attempt calls :meth:`release` (returning the slot to
available -- a *failed* attempt does not burn a single-use grant's one
permitted use); a successful attempt calls :meth:`commit` (which
permanently increments the use counter and records the idempotency
outcome for crash-recovery lookups).

See docs/storage-semantics.md and docs/crash-recovery.md.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class GrantStore(Protocol):
    def reserve(self, grant_id: str, max_uses: int) -> bool:
        """Atomically reserve one use of ``grant_id``.

        Returns ``False`` (never raises for the "already reserved by
        someone else" or "exhausted" or "revoked" cases) if the grant is
        revoked, already reserved by another in-flight attempt, or has no
        remaining uses. Returns ``True`` if this caller now exclusively
        holds the reservation.
        """
        ...

    def release(self, grant_id: str) -> None:
        """Release a held reservation after a failed attempt, without
        consuming a use."""
        ...

    def commit(self, grant_id: str, idempotency_key: str, outcome_ref: str) -> None:
        """Finalize a successful attempt: permanently consume one use and
        record the idempotency outcome."""
        ...

    def revoke(self, grant_id: str) -> None: ...

    def is_revoked(self, grant_id: str) -> bool: ...

    def get_use_count(self, grant_id: str) -> int: ...

    def get_idempotent_outcome(self, idempotency_key: str) -> str | None:
        """Look up a previously committed outcome by idempotency key, for
        crash-recovery: never blindly retry a consequential external action
        without first checking whether it already happened."""
        ...

    def record_idempotent_outcome(self, idempotency_key: str, outcome_ref: str) -> None:
        """Backfill the idempotency ledger directly, independent of any
        grant reservation. Used only by ambiguous-outcome crash recovery
        (see docs/crash-recovery.md) after independently re-observing
        external state -- never as a substitute for the normal
        reserve -> commit path."""
        ...


__all__ = ["GrantStore"]
