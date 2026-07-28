"""Durable, append-only SQLite backend for the audit journal.

Rows are never updated or deleted by this class -- only inserted, in
strictly increasing ``sequence`` order -- and :meth:`AuditJournal.verify_chain`
still recomputes/validates the full hash chain against whatever this
backend returns, so tampering with the underlying database file directly
(bypassing this class) is still detected.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from karmasakshi.audit.events import AuditEvent
from karmasakshi.canonical.serialize import canonical_json_bytes
from karmasakshi.errors import AuditWriteError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY,
    payload BLOB NOT NULL
);
"""


class SQLiteAuditBackend:
    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def append(self, event: AuditEvent) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO audit_events(sequence, payload) VALUES (?, ?)",
                    (event.sequence, canonical_json_bytes(event)),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                self._conn.rollback()
                raise AuditWriteError(
                    f"failed to durably write audit event sequence={event.sequence}"
                ) from exc

    def all_events(self) -> list[AuditEvent]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM audit_events ORDER BY sequence ASC"
            ).fetchall()
        return [AuditEvent.model_validate_json(row[0]) for row in rows]

    def last_event(self) -> AuditEvent | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        return AuditEvent.model_validate_json(row[0]) if row else None


__all__ = ["SQLiteAuditBackend"]
