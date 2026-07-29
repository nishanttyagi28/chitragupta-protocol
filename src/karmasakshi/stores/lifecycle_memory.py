"""In-process lifecycle store (Phase 13)."""

from __future__ import annotations

import threading

from karmasakshi.state_machine.states import LifecycleState


class InMemoryLifecycleStore:
    """Thread-safe process-local lifecycle state."""

    def __init__(self) -> None:
        self._states: dict[str, LifecycleState] = {}
        self._lock = threading.Lock()

    def get(self, manifest_id: str) -> LifecycleState | None:
        with self._lock:
            return self._states.get(manifest_id)

    def set(self, manifest_id: str, state: LifecycleState) -> None:
        with self._lock:
            self._states[manifest_id] = state

    def compare_and_set(
        self,
        manifest_id: str,
        expected: LifecycleState | None,
        new_state: LifecycleState,
    ) -> bool:
        with self._lock:
            current = self._states.get(manifest_id)
            if current != expected:
                return False
            self._states[manifest_id] = new_state
            return True


__all__ = ["InMemoryLifecycleStore"]
