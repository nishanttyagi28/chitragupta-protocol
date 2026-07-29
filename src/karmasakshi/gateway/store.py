"""Durable SQLite-backed store for the Gateway's organizations and users
(commercial Milestone A).

Local/single-node durability, the same posture as the protocol core's
other SQLite backends (grants/audit/lifecycle/outbox) -- safe for
multiple processes sharing one database file under SQLite's writer
lock, not a multi-node distributed store. See docs/gateway.md.

**Local development authentication only.** Passwords are hashed with
PBKDF2-HMAC-SHA256 (a real key-derivation function, not a production
identity-provider integration) -- there is no SSO, no MFA, no session
management, and no server-enforced RBAC here yet (Milestone B/C). See
docs/limitations.md and docs/product/SECURITY_FAQ.md.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from karmasakshi.errors import (
    CrossOrganizationAccessError,
    GatewayAuthenticationError,
    GatewayUserAlreadyExistsError,
    GatewayUserNotFoundError,
    OrganizationAlreadyExistsError,
    OrganizationNotFoundError,
    OrganizationSuspendedError,
    StoreUnavailableError,
)
from karmasakshi.gateway.migrations import apply_migrations
from karmasakshi.gateway.models import (
    GatewayUser,
    GatewayUserRole,
    Organization,
    OrganizationStatus,
)

_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16


def _hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return digest.hex()


def _safe_rollback(conn: sqlite3.Connection) -> None:
    with contextlib.suppress(sqlite3.Error):
        conn.rollback()


def _row_to_organization(row: sqlite3.Row) -> Organization:
    return Organization(
        org_id=row["org_id"],
        name=row["name"],
        status=OrganizationStatus(row["status"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def _row_to_user(row: sqlite3.Row) -> GatewayUser:
    return GatewayUser(
        user_id=row["user_id"],
        org_id=row["org_id"],
        email=row["email"],
        display_name=row["display_name"],
        role=GatewayUserRole(row["role"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


class GatewayStore:
    """Organization + user durable storage, with explicit migrations
    applied at construction time."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._conn = sqlite3.connect(self._path, timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._lock = threading.Lock()
        with self._lock:
            apply_migrations(self._conn)

    def close(self) -> None:
        self._conn.close()

    # --- organizations --------------------------------------------------------

    def create_organization(self, org_id: str, name: str) -> Organization:
        org = Organization(org_id=org_id, name=name, created_at=datetime.now(timezone.utc))
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO organizations(org_id, name, status, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (org.org_id, org.name, org.status.value, org.created_at.isoformat()),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                _safe_rollback(self._conn)
                raise OrganizationAlreadyExistsError(
                    f"organization {org_id!r} already exists"
                ) from exc
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(f"create_organization({org_id!r}) failed") from exc
        return org

    def get_organization(self, org_id: str) -> Organization:
        with self._lock:
            try:
                row = self._conn.execute(
                    "SELECT * FROM organizations WHERE org_id = ?", (org_id,)
                ).fetchone()
            except sqlite3.Error as exc:
                raise StoreUnavailableError(f"get_organization({org_id!r}) failed") from exc
        if row is None:
            raise OrganizationNotFoundError(f"no such organization: {org_id!r}")
        return _row_to_organization(row)

    def list_organizations(self) -> list[Organization]:
        with self._lock:
            try:
                rows = self._conn.execute("SELECT * FROM organizations ORDER BY org_id").fetchall()
            except sqlite3.Error as exc:
                raise StoreUnavailableError("list_organizations() failed") from exc
        return [_row_to_organization(r) for r in rows]

    def set_organization_status(self, org_id: str, status: OrganizationStatus) -> Organization:
        with self._lock:
            try:
                cur = self._conn.execute(
                    "UPDATE organizations SET status = ? WHERE org_id = ?",
                    (status.value, org_id),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(f"set_organization_status({org_id!r}) failed") from exc
        if cur.rowcount == 0:
            raise OrganizationNotFoundError(f"no such organization: {org_id!r}")
        return self.get_organization(org_id)

    def require_active_organization(self, org_id: str) -> Organization:
        """Fetch an organization and fail closed unless it is active --
        the check every org-scoped Gateway operation should run first."""
        org = self.get_organization(org_id)
        if not org.is_active():
            raise OrganizationSuspendedError(f"organization {org_id!r} is suspended")
        return org

    # --- users ------------------------------------------------------------

    def create_user(
        self,
        *,
        user_id: str,
        org_id: str,
        email: str,
        display_name: str,
        password: str,
        role: GatewayUserRole = GatewayUserRole.MEMBER,
    ) -> GatewayUser:
        self.require_active_organization(org_id)
        user = GatewayUser(
            user_id=user_id,
            org_id=org_id,
            email=email,
            display_name=display_name,
            role=role,
            created_at=datetime.now(timezone.utc),
        )
        salt = secrets.token_bytes(_SALT_BYTES)
        password_hash = _hash_password(password, salt)
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO gateway_users("
                    "user_id, org_id, email, display_name, role, "
                    "password_hash, password_salt, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        user.user_id,
                        user.org_id,
                        user.email,
                        user.display_name,
                        user.role.value,
                        password_hash,
                        salt.hex(),
                        user.created_at.isoformat(),
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                _safe_rollback(self._conn)
                raise GatewayUserAlreadyExistsError(
                    f"user {email!r} already exists in organization {org_id!r}"
                ) from exc
            except sqlite3.Error as exc:
                _safe_rollback(self._conn)
                raise StoreUnavailableError(f"create_user({email!r}) failed") from exc
        return user

    def get_user(self, org_id: str, email: str) -> GatewayUser:
        with self._lock:
            try:
                row = self._conn.execute(
                    "SELECT * FROM gateway_users WHERE org_id = ? AND email = ?",
                    (org_id, email),
                ).fetchone()
            except sqlite3.Error as exc:
                raise StoreUnavailableError(f"get_user({email!r}) failed") from exc
        if row is None:
            raise GatewayUserNotFoundError(f"no user {email!r} in organization {org_id!r}")
        return _row_to_user(row)

    def list_users(self, org_id: str) -> list[GatewayUser]:
        self.require_active_organization(org_id)
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT * FROM gateway_users WHERE org_id = ? ORDER BY email", (org_id,)
                ).fetchall()
            except sqlite3.Error as exc:
                raise StoreUnavailableError(f"list_users({org_id!r}) failed") from exc
        return [_row_to_user(r) for r in rows]

    def authenticate(self, *, org_id: str, email: str, password: str) -> GatewayUser:
        """Verify ``password`` for ``email`` scoped to ``org_id``. Fails
        closed (``GatewayAuthenticationError``) on any of: unknown
        organization, suspended organization, unknown email in that
        organization, or a wrong password -- never distinguishing which,
        so an attacker cannot enumerate valid emails via error messages.
        """
        try:
            self.require_active_organization(org_id)
            with self._lock:
                try:
                    row = self._conn.execute(
                        "SELECT * FROM gateway_users WHERE org_id = ? AND email = ?",
                        (org_id, email),
                    ).fetchone()
                except sqlite3.Error as exc:
                    raise StoreUnavailableError(f"authenticate({email!r}) failed") from exc
        except (OrganizationNotFoundError, OrganizationSuspendedError) as exc:
            raise GatewayAuthenticationError("authentication failed") from exc
        if row is None:
            raise GatewayAuthenticationError("authentication failed")
        salt = bytes.fromhex(row["password_salt"])
        expected = _hash_password(password, salt)
        if not hmac.compare_digest(expected, row["password_hash"]):
            raise GatewayAuthenticationError("authentication failed")
        return _row_to_user(row)

    def assert_user_belongs_to_organization(self, user: GatewayUser, org_id: str) -> None:
        """Fail closed if ``user`` is not a member of ``org_id`` -- the
        check every org-scoped request handler should run against the
        authenticated user before touching that org's data."""
        if user.org_id != org_id:
            raise CrossOrganizationAccessError(
                f"user {user.user_id!r} belongs to organization {user.org_id!r}, not {org_id!r}"
            )


def default_gateway_db_path(data_dir: Path) -> Path:
    return Path(data_dir) / "gateway.db"


__all__ = ["GatewayStore", "default_gateway_db_path"]
