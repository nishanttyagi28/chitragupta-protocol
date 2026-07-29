"""SQLite-backed lifecycle store (Phase 13).

Durable for local/single-node use. Multiple processes on one machine
sharing one database file are safe under SQLite's writer lock; multiple
machines are not. Never claim multi-node lifecycle consensus from this
backend.
"""

from __future__ import annotations

import contextlib
import sqlite3
import threading
from pathlib import Path

from karmasakshi.errors import StoreUnavailableError
from karmasakshi.state_machine.states import LifecycleState

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lifecycle_state (
    manifest_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""


def _safe_rollback(conn: sqlite3.Connection) -> None:
    with contextlib.suppress(sqlite3.Error):
        conn.rollback()


class SQLiteLifecycleStore:
    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._conn = sqlite3.connect(self._path, timeout=30, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get(self, manifest_id: str) -> LifecycleState | None:
        with self._lock:
            try:
                cur = self._conn.execute(
                    "SELECT state FROM lifecycle_state WHERE manifest_id = ?",
                    (manifest_id,),
                )
                row = cur.fetchone()
            except sqlite3.Error as exc:
                raise StoreUnavailableError(
                    f"sqlite lifecycle get() failed for {manifest_id}"
                ) from exc
        if row is None:
            return None
        try:
            return LifecycleState(row[0])
        except ValueError as exc:
            raise StoreUnavailableError(
                f"sqlite lifecycle store holds unknown state {row[0]!r} for {manifest_id}"
            ) from exc

    def set(self, manifest_id: str, state: LifecycleState) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO lifecycle_state(manifest_id, state) VALUES (?, ?) "
                    "ON CONFLICT(manifest_id) DO UPDATE SET state = excluded.state, "
                    "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
                    (manifest_id, state.value),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(
                    f"sqlite lifecycle set() failed for {manifest_id}"
                ) from exc

    def compare_and_set(
        self,
        manifest_id: str,
        expected: LifecycleState | None,
        new_state: LifecycleState,
    ) -> bool:
        with self._lock:
            try:
                if expected is None:
                    cur = self._conn.execute(
                        "INSERT OR IGNORE INTO lifecycle_state(manifest_id, state) VALUES (?, ?)",
                        (manifest_id, new_state.value),
                    )
                    self._conn.commit()
                    return cur.rowcount == 1
                cur = self._conn.execute(
                    "UPDATE lifecycle_state SET state = ?, "
                    "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') "
                    "WHERE manifest_id = ? AND state = ?",
                    (new_state.value, manifest_id, expected.value),
                )
                self._conn.commit()
                return cur.rowcount == 1
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(
                    f"sqlite lifecycle compare_and_set() failed for {manifest_id}"
                ) from exc


__all__ = ["SQLiteLifecycleStore"]
