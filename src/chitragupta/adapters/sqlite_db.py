"""SQLite database effect adapter.

Operates on a single controlled demo table (default ``ledger_accounts``)
with parameterized SQL only -- there is no code path that accepts
model-generated SQL text. Optimistic concurrency (a ``version`` column) is
the TOCTOU precondition; the same version predicate also makes a duplicate
``commit()`` call fail rather than silently double-apply, giving the
adapter its own idempotency defense in depth on top of the engine's
idempotency ledger.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from chitragupta.adapters.base import (
    CommitResult,
    CompensationResult,
    OutcomeProof,
    PreconditionResult,
)
from chitragupta.canonical.serialize import digest_bytes
from chitragupta.domain.common import AdapterIdentity, Principal, StateFingerprint
from chitragupta.domain.enums import (
    BlastRadiusClassification,
    ReversibilityClassification,
    RiskClassification,
    StateFingerprintKind,
)
from chitragupta.domain.manifest import EffectManifest
from chitragupta.errors import BlastRadiusExceededError

RowOperation = Literal["insert", "update", "delete"]


@dataclass(frozen=True)
class RowEffectRequest:
    """A structured, validated request -- never raw SQL."""

    operation: RowOperation
    row_id: str
    actor: Principal
    principal: Principal
    new_balance: int | None = None  # required for insert/update
    idempotency_key: str = ""
    nonce: str = ""
    ttl_seconds: int = 300


def _row_digest(row: tuple[Any, ...] | None) -> str:
    if row is None:
        return digest_bytes(b"<absent>")
    return digest_bytes(repr(row).encode("utf-8"))


def _int_param(value: object) -> int:
    if not isinstance(value, int):
        raise TypeError(f"expected an int manifest parameter, got {type(value).__name__}")
    return value


class SQLiteRowAdapter:
    """Insert/update/delete rows in a single demo ``ledger_accounts`` table."""

    adapter_id = "sqlite.row"
    adapter_version = "1.0.0"

    def __init__(
        self, db_path: str, table: str = "ledger_accounts", max_affected_rows: int = 1
    ) -> None:
        self.db_path = db_path
        self.table = table
        self.max_affected_rows = max_affected_rows
        self._identity = AdapterIdentity(
            adapter_id=self.adapter_id, adapter_version=self.adapter_version
        )
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {self.table} ("
                "id TEXT PRIMARY KEY, balance INTEGER NOT NULL, "
                "version INTEGER NOT NULL DEFAULT 0, updated_at TEXT)"
            )
            conn.commit()
        finally:
            conn.close()

    def _fetch(self, conn: sqlite3.Connection, row_id: str) -> tuple[Any, ...] | None:
        # self.table is a fixed constructor-time config value (never derived from a
        # manifest/agent/user), so this f-string is safe; all row values are still
        # bound as parameters, never interpolated.
        row = conn.execute(
            f"SELECT balance, version FROM {self.table} WHERE id = ?",  # noqa: S608
            (row_id,),
        ).fetchone()
        return tuple(row) if row is not None else None

    def prepare(self, request: RowEffectRequest, context: Any) -> EffectManifest:
        conn = self._connect()
        try:
            existing = self._fetch(conn, request.row_id)
        finally:
            conn.close()

        now = datetime.now(timezone.utc)
        if request.operation == "insert":
            reversibility = ReversibilityClassification.COMPENSATABLE
            expected_version = 0
        elif request.operation == "update":
            reversibility = ReversibilityClassification.COMPENSATABLE
            expected_version = existing[1] if existing else 0
        else:  # delete
            reversibility = ReversibilityClassification.IRREVERSIBLE
            expected_version = existing[1] if existing else 0

        parameters: dict[str, Any] = {"operation": request.operation, "row_id": request.row_id}
        if request.new_balance is not None:
            parameters["new_balance"] = request.new_balance
        if existing is not None:
            parameters["previous_balance"] = existing[0]

        return EffectManifest(
            manifest_id=str(uuid.uuid4()),
            effect_type=f"sqlite.row.{request.operation}",
            actor=request.actor,
            principal=request.principal,
            adapter=self._identity,
            target_resource=f"sqlite:{self.table}/{request.row_id}",
            parameters=parameters,
            before_state_digest=_row_digest(existing),
            state_fingerprint=StateFingerprint(
                kind=StateFingerprintKind.ROW_VERSION, value=str(expected_version)
            ),
            risk=RiskClassification.MEDIUM,
            reversibility=reversibility,
            blast_radius=BlastRadiusClassification.SINGLE_RESOURCE,
            idempotency_key=request.idempotency_key or f"sqlite-{request.row_id}",
            created_at=now,
            expires_at=now + timedelta(seconds=request.ttl_seconds),
            nonce=request.nonce or f"nonce-{request.row_id}",
        )

    def validate_preconditions(self, manifest: EffectManifest, context: Any) -> PreconditionResult:
        row_id = str(manifest.parameters["row_id"])
        assert manifest.state_fingerprint is not None
        expected_version = int(manifest.state_fingerprint.value)
        conn = self._connect()
        try:
            existing = self._fetch(conn, row_id)
        finally:
            conn.close()

        operation = manifest.parameters["operation"]
        if operation == "insert":
            if existing is not None:
                return PreconditionResult(satisfied=False, reason="row already exists")
            return PreconditionResult(satisfied=True)

        if existing is None:
            return PreconditionResult(satisfied=False, reason="row no longer exists")
        current_version = int(existing[1])
        if current_version != expected_version:
            reason = f"row version changed: expected {expected_version}, observed {current_version}"
            return PreconditionResult(
                satisfied=False,
                reason=reason,
                observed_fingerprint=StateFingerprint(
                    kind=StateFingerprintKind.ROW_VERSION, value=str(current_version)
                ),
            )
        return PreconditionResult(satisfied=True)

    def commit(self, manifest: EffectManifest, grant: Any, context: Any) -> CommitResult:
        row_id = str(manifest.parameters["row_id"])
        operation = manifest.parameters["operation"]
        assert manifest.state_fingerprint is not None
        expected_version = int(manifest.state_fingerprint.value)
        now_iso = datetime.now(timezone.utc).isoformat()

        conn = self._connect()
        try:
            if operation == "insert":
                new_balance = _int_param(manifest.parameters["new_balance"])
                try:
                    cur = conn.execute(
                        f"INSERT INTO {self.table}(id, balance, version, updated_at) "  # noqa: S608
                        "VALUES (?, ?, 0, ?)",
                        (row_id, new_balance, now_iso),
                    )
                except sqlite3.IntegrityError:
                    conn.rollback()
                    return CommitResult(
                        success=False,
                        idempotency_key=manifest.idempotency_key,
                        detail="row already exists",
                    )
                affected = cur.rowcount
            elif operation == "update":
                new_balance = _int_param(manifest.parameters["new_balance"])
                cur = conn.execute(
                    f"UPDATE {self.table} SET balance = ?, version = version + 1, "  # noqa: S608
                    "updated_at = ? WHERE id = ? AND version = ?",
                    (new_balance, now_iso, row_id, expected_version),
                )
                affected = cur.rowcount
            else:  # delete
                cur = conn.execute(
                    f"DELETE FROM {self.table} WHERE id = ? AND version = ?",  # noqa: S608
                    (row_id, expected_version),
                )
                affected = cur.rowcount

            if affected > self.max_affected_rows:
                conn.rollback()
                raise BlastRadiusExceededError(
                    f"operation would affect {affected} rows, ceiling is {self.max_affected_rows}"
                )
            if affected == 0:
                conn.rollback()
                return CommitResult(
                    success=False,
                    idempotency_key=manifest.idempotency_key,
                    detail="no matching row (version mismatch, missing, or already deleted)",
                )
            conn.commit()
            after = self._fetch(conn, row_id)
        finally:
            conn.close()

        return CommitResult(
            success=True,
            idempotency_key=manifest.idempotency_key,
            provider_reference=f"{self.table}:{row_id}",
            after_state_digest=_row_digest(after),
        )

    def verify(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> OutcomeProof:
        row_id = str(manifest.parameters["row_id"])
        conn = self._connect()
        try:
            row = self._fetch(conn, row_id)
        finally:
            conn.close()
        observed_digest = _row_digest(row)
        operation = manifest.parameters["operation"]
        if operation == "delete":
            matched = row is None
        else:
            expected_balance = _int_param(manifest.parameters["new_balance"])
            matched = row is not None and int(row[0]) == expected_balance
        return OutcomeProof(
            matched_expected=matched,
            observed_at=datetime.now(timezone.utc),
            observed_after_state_digest=observed_digest,
        )

    def compensate(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> CompensationResult:
        operation = manifest.parameters["operation"]
        row_id = str(manifest.parameters["row_id"])

        if operation == "delete":
            return CompensationResult(
                attempted=False,
                succeeded=False,
                reason=(
                    "row deletion is treated as irreversible by this reference adapter; "
                    "reinserting a snapshot would not guarantee identical downstream state"
                ),
            )

        conn = self._connect()
        try:
            if operation == "insert":
                cur = conn.execute(
                    f"DELETE FROM {self.table} WHERE id = ?",  # noqa: S608
                    (row_id,),
                )
                ok = cur.rowcount > 0
                conn.commit()
                return CompensationResult(
                    attempted=True,
                    succeeded=ok,
                    reason=None if ok else "row was already gone",
                )
            # update: restore previous_balance if present
            previous_balance = manifest.parameters.get("previous_balance")
            if previous_balance is None:
                return CompensationResult(
                    attempted=False,
                    succeeded=False,
                    reason="no previous balance recorded to restore",
                )
            cur = conn.execute(
                f"UPDATE {self.table} SET balance = ?, version = version + 1 "  # noqa: S608
                "WHERE id = ?",
                (previous_balance, row_id),
            )
            ok = cur.rowcount > 0
            conn.commit()
            return CompensationResult(
                attempted=True, succeeded=ok, reason=None if ok else "row no longer exists"
            )
        finally:
            conn.close()


__all__ = ["RowEffectRequest", "SQLiteRowAdapter"]
