"""Process-local tenant registry (Phase 19)."""

from __future__ import annotations

from threading import RLock

from karmasakshi.errors import TenantIsolationError, UnknownTenantError
from karmasakshi.tenant.model import Tenant


class TenantRegistry:
    """Allow-list of tenants known to this control-plane process.

    Not a multi-region directory service — operators provision the same
    registry contents on each node.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._tenants: dict[str, Tenant] = {}

    def register(self, tenant: Tenant) -> Tenant:
        with self._lock:
            self._tenants[tenant.tenant_id] = tenant
            return tenant

    def get(self, tenant_id: str) -> Tenant | None:
        with self._lock:
            return self._tenants.get(tenant_id)

    def require(self, tenant_id: str) -> Tenant:
        tenant = self.get(tenant_id)
        if tenant is None:
            raise UnknownTenantError(
                f"tenant {tenant_id!r} is unknown; refuse to proceed (fail closed)"
            )
        if tenant.status != "active":
            raise TenantIsolationError(
                f"tenant {tenant_id!r} is {tenant.status}; refuse to proceed (fail closed)"
            )
        return tenant

    def suspend(self, tenant_id: str) -> Tenant:
        with self._lock:
            existing = self._tenants.get(tenant_id)
            if existing is None:
                raise UnknownTenantError(
                    f"cannot suspend unknown tenant {tenant_id!r} (fail closed)"
                )
            updated = Tenant(
                tenant_id=existing.tenant_id,
                display_name=existing.display_name,
                status="suspended",
                created_at=existing.created_at,
            )
            self._tenants[tenant_id] = updated
            return updated

    def list_tenants(self) -> tuple[Tenant, ...]:
        with self._lock:
            return tuple(sorted(self._tenants.values(), key=lambda t: t.tenant_id))

    def __len__(self) -> int:
        with self._lock:
            return len(self._tenants)


__all__ = ["TenantRegistry"]
