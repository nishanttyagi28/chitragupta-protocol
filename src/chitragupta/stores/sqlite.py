"""SQLite-backed grant store.

Durable for local/single-node use. This is explicitly **not** a
horizontally distributed production backend -- SQLite serializes writers
at the file level, which is exactly what we lean on for atomicity here (see
docs/storage-semantics.md). Multiple processes on the same machine sharing
one database file are safe; multiple machines are not (use the Redis
backend for that).
"""

from __future__ import annotations

import contextlib
import sqlite3
import threading
from pathlib import Path

from chitragupta.errors import StoreUnavailableError


def _safe_rollback(conn: sqlite3.Connection) -> None:
    """Best-effort rollback: if the connection itself is dead, rollback()
    can raise too -- that secondary failure must never mask the
    StoreUnavailableError the caller is about to raise (fail closed either
    way, but with a clear, single error)."""
    with contextlib.suppress(sqlite3.Error):
        conn.rollback()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS grant_slots (
    grant_id TEXT PRIMARY KEY,
    max_uses INTEGER NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    reserved INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS idempotency_ledger (
    idempotency_key TEXT PRIMARY KEY,
    outcome_ref TEXT NOT NULL
);
"""


class SQLiteGrantStore:
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

    def reserve(self, grant_id: str, max_uses: int) -> bool:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO grant_slots(grant_id, max_uses) VALUES (?, ?)",
                    (grant_id, max_uses),
                )
                cur = self._conn.execute(
                    "UPDATE grant_slots SET reserved = 1 "
                    "WHERE grant_id = ? AND revoked = 0 AND reserved = 0 AND uses < max_uses",
                    (grant_id,),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(
                    f"sqlite reserve() failed for grant {grant_id}"
                ) from exc
            return cur.rowcount == 1

    def release(self, grant_id: str) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "UPDATE grant_slots SET reserved = 0 WHERE grant_id = ?", (grant_id,)
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(
                    f"sqlite release() failed for grant {grant_id}"
                ) from exc

    def commit(self, grant_id: str, idempotency_key: str, outcome_ref: str) -> None:
        with self._lock:
            try:
                cur = self._conn.execute(
                    "UPDATE grant_slots SET uses = uses + 1, reserved = 0 "
                    "WHERE grant_id = ? AND reserved = 1",
                    (grant_id,),
                )
                if cur.rowcount != 1:
                    _safe_rollback(self._conn)
                    raise StoreUnavailableError(
                        f"commit() called for grant {grant_id!r} without a held reservation"
                    )
                self._conn.execute(
                    "INSERT OR REPLACE INTO idempotency_ledger(idempotency_key, outcome_ref) "
                    "VALUES (?, ?)",
                    (idempotency_key, outcome_ref),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(f"sqlite commit() failed for grant {grant_id}") from exc

    def revoke(self, grant_id: str) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO grant_slots(grant_id, max_uses) VALUES (?, 0)",
                    (grant_id,),
                )
                self._conn.execute(
                    "UPDATE grant_slots SET revoked = 1 WHERE grant_id = ?", (grant_id,)
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(f"sqlite revoke() failed for grant {grant_id}") from exc

    def is_revoked(self, grant_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT revoked FROM grant_slots WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            return bool(row[0]) if row else False

    def get_use_count(self, grant_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT uses FROM grant_slots WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            return int(row[0]) if row else 0

    def get_idempotent_outcome(self, idempotency_key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT outcome_ref FROM idempotency_ledger WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            return str(row[0]) if row else None

    def record_idempotent_outcome(self, idempotency_key: str, outcome_ref: str) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO idempotency_ledger(idempotency_key, outcome_ref) "
                    "VALUES (?, ?)",
                    (idempotency_key, outcome_ref),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(
                    f"sqlite record_idempotent_outcome() failed for key {idempotency_key}"
                ) from exc


__all__ = ["SQLiteGrantStore"]
