"""Explicit, versioned SQLite migrations for the Gateway's durable
organization model (commercial Milestone A).

The protocol core's single-table stores (grants/audit/lifecycle/outbox)
use an ad-hoc ``CREATE TABLE IF NOT EXISTS`` script because each owns
exactly one stable table shape. The Gateway's schema is expected to
evolve across commercial milestones (Milestone B adds RBAC/approval
groups, Milestone C adds retention, etc.), so it tracks exactly which
migrations a given database has applied in a ``schema_migrations``
table and applies only the ones it hasn't seen yet, in id order, one
transaction per migration -- a real migration system, not a bigger
idempotent script.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from karmasakshi.errors import GatewayMigrationError


@dataclass(frozen=True)
class Migration:
    id: int
    name: str
    sql: str


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        id=1,
        name="create_organizations",
        sql="""
            CREATE TABLE organizations (
                org_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """,
    ),
    Migration(
        id=2,
        name="create_gateway_users",
        sql="""
            CREATE TABLE gateway_users (
                user_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL REFERENCES organizations(org_id),
                email TEXT NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(org_id, email)
            )
        """,
    ),
    Migration(
        id=3,
        name="create_gateway_agents",
        sql="""
            CREATE TABLE gateway_agents (
                org_id TEXT NOT NULL REFERENCES organizations(org_id),
                agent_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(org_id, agent_id)
            )
        """,
    ),
    Migration(
        id=4,
        name="create_gateway_adapters",
        sql="""
            CREATE TABLE gateway_adapters (
                org_id TEXT NOT NULL REFERENCES organizations(org_id),
                adapter_id TEXT NOT NULL,
                adapter_version TEXT NOT NULL,
                effect_types_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(org_id, adapter_id)
            )
        """,
    ),
)


def _ensure_migrations_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "id INTEGER PRIMARY KEY, "
        "name TEXT NOT NULL, "
        "applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))"
    )
    conn.commit()


def applied_migration_ids(conn: sqlite3.Connection) -> set[int]:
    _ensure_migrations_table(conn)
    return {row[0] for row in conn.execute("SELECT id FROM schema_migrations")}


def apply_migrations(conn: sqlite3.Connection) -> list[int]:
    """Apply every migration not yet recorded against ``conn``, in id
    order. Returns the ids actually applied this call (empty if the
    database was already current). Fails closed: a migration that raises
    rolls back that migration's own transaction and stops -- later
    migrations are never applied out of order over a failed one.
    """
    _ensure_migrations_table(conn)
    already_applied = applied_migration_ids(conn)
    newly_applied: list[int] = []
    for migration in sorted(MIGRATIONS, key=lambda m: m.id):
        if migration.id in already_applied:
            continue
        try:
            conn.execute(migration.sql)
            conn.execute(
                "INSERT INTO schema_migrations(id, name) VALUES (?, ?)",
                (migration.id, migration.name),
            )
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise GatewayMigrationError(
                f"migration {migration.id} ({migration.name}) failed to apply: {exc}"
            ) from exc
        newly_applied.append(migration.id)
    return newly_applied


__all__ = ["MIGRATIONS", "Migration", "applied_migration_ids", "apply_migrations"]
