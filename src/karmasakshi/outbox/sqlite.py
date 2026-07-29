"""SQLite transactional outbox (Phase 15). Single-node only."""

from __future__ import annotations

import contextlib
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from karmasakshi.errors import StoreUnavailableError
from karmasakshi.outbox.memory import OutboxConflictError
from karmasakshi.outbox.model import OutboxEntry

_SCHEMA = """
CREATE TABLE IF NOT EXISTS commit_outbox (
    idempotency_key TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    outcome_ref TEXT,
    schema_version TEXT NOT NULL
);
"""


def _safe_rollback(conn: sqlite3.Connection) -> None:
    with contextlib.suppress(sqlite3.Error):
        conn.rollback()


class SQLiteOutboxStore:
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

    def record_pending(self, entry: OutboxEntry) -> None:
        if entry.status != "pending":
            raise OutboxConflictError("record_pending requires status=pending")
        with self._lock:
            try:
                existing = self._fetch(entry.idempotency_key)
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
                self._conn.execute(
                    "INSERT INTO commit_outbox("
                    "idempotency_key, grant_id, manifest_id, manifest_hash, "
                    "status, created_at, outcome_ref, schema_version"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry.idempotency_key,
                        entry.grant_id,
                        entry.manifest_id,
                        entry.manifest_hash,
                        entry.status,
                        entry.created_at.isoformat(),
                        entry.outcome_ref,
                        entry.schema_version,
                    ),
                )
                self._conn.commit()
            except OutboxConflictError:
                raise
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(
                    f"sqlite outbox record_pending failed for {entry.idempotency_key}"
                ) from exc

    def get(self, idempotency_key: str) -> OutboxEntry | None:
        with self._lock:
            try:
                return self._fetch(idempotency_key)
            except sqlite3.Error as exc:
                raise StoreUnavailableError(
                    f"sqlite outbox get failed for {idempotency_key}"
                ) from exc

    def mark_confirmed(self, idempotency_key: str, outcome_ref: str) -> None:
        with self._lock:
            try:
                entry = self._fetch(idempotency_key)
                if entry is None:
                    raise OutboxConflictError(f"unknown outbox key {idempotency_key!r}")
                if entry.status == "confirmed":
                    return
                if entry.status != "pending":
                    raise OutboxConflictError(
                        f"cannot confirm outbox key {idempotency_key!r} in status {entry.status}"
                    )
                cur = self._conn.execute(
                    "UPDATE commit_outbox SET status = 'confirmed', outcome_ref = ? "
                    "WHERE idempotency_key = ? AND status = 'pending'",
                    (outcome_ref, idempotency_key),
                )
                self._conn.commit()
                if cur.rowcount != 1:
                    raise OutboxConflictError(f"outbox confirm race for {idempotency_key!r}")
            except OutboxConflictError:
                raise
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(
                    f"sqlite outbox mark_confirmed failed for {idempotency_key}"
                ) from exc

    def mark_abandoned(self, idempotency_key: str) -> None:
        with self._lock:
            try:
                entry = self._fetch(idempotency_key)
                if entry is None:
                    raise OutboxConflictError(f"unknown outbox key {idempotency_key!r}")
                if entry.status == "abandoned":
                    return
                if entry.status != "pending":
                    raise OutboxConflictError(
                        f"cannot abandon outbox key {idempotency_key!r} in status {entry.status}"
                    )
                cur = self._conn.execute(
                    "UPDATE commit_outbox SET status = 'abandoned' "
                    "WHERE idempotency_key = ? AND status = 'pending'",
                    (idempotency_key,),
                )
                self._conn.commit()
                if cur.rowcount != 1:
                    raise OutboxConflictError(f"outbox abandon race for {idempotency_key!r}")
            except OutboxConflictError:
                raise
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(
                    f"sqlite outbox mark_abandoned failed for {idempotency_key}"
                ) from exc

    def list_pending(self) -> list[OutboxEntry]:
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT idempotency_key, grant_id, manifest_id, manifest_hash, "
                    "status, created_at, outcome_ref, schema_version "
                    "FROM commit_outbox WHERE status = 'pending' ORDER BY created_at ASC"
                ).fetchall()
            except sqlite3.Error as exc:
                raise StoreUnavailableError("sqlite outbox list_pending failed") from exc
        return [self._row_to_entry(row) for row in rows]

    def _fetch(self, idempotency_key: str) -> OutboxEntry | None:
        row = self._conn.execute(
            "SELECT idempotency_key, grant_id, manifest_id, manifest_hash, "
            "status, created_at, outcome_ref, schema_version "
            "FROM commit_outbox WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        return None if row is None else self._row_to_entry(row)

    def _row_to_entry(self, row: tuple[Any, ...]) -> OutboxEntry:
        status = str(row[4])
        if status not in ("pending", "confirmed", "abandoned"):
            raise StoreUnavailableError(f"sqlite outbox holds unknown status {status!r}")
        return OutboxEntry(
            idempotency_key=str(row[0]),
            grant_id=str(row[1]),
            manifest_id=str(row[2]),
            manifest_hash=str(row[3]),
            status=status,  # narrowed above
            created_at=datetime.fromisoformat(str(row[5])),
            outcome_ref=None if row[6] is None else str(row[6]),
            schema_version=str(row[7]),
        )


__all__ = ["SQLiteOutboxStore"]
