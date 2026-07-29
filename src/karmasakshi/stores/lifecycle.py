"""Lifecycle state store contract (extreme-v2 Phase 13).

The audit journal remains the tamper-evident record of transitions.
A :class:`LifecycleStore` is durable convenience state so a restarted
host can enforce the next legal transition without relying solely on
audit replay. Single-node SQLite is supported; this is not a
multi-machine consensus store.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from karmasakshi.state_machine.states import LifecycleState


@runtime_checkable
class LifecycleStore(Protocol):
    def get(self, manifest_id: str) -> LifecycleState | None:
        """Return the stored state, or ``None`` if never written."""
        ...

    def set(self, manifest_id: str, state: LifecycleState) -> None:
        """Persist ``state`` as the current lifecycle state for ``manifest_id``."""
        ...

    def compare_and_set(
        self,
        manifest_id: str,
        expected: LifecycleState | None,
        new_state: LifecycleState,
    ) -> bool:
        """Atomically set ``new_state`` iff the stored value equals ``expected``.

        ``expected is None`` means the manifest must not yet have a row.
        Returns ``True`` on success, ``False`` if the precondition failed
        (never invents success under contention).
        """
        ...


__all__ = ["LifecycleStore"]
