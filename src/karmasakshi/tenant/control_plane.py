"""Multi-tenant control-plane partition (Phase 19).

Each tenant gets an isolated :class:`~karmasakshi.api.state.ApiState`.
Cross-tenant lookups fail closed. This is process-local isolation for
evaluation and single-node self-host — not a distributed tenancy fabric.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock

from karmasakshi.api.state import ApiState, build_default_state
from karmasakshi.errors import TenantIsolationError
from karmasakshi.tenant.enforce import require_active_tenant
from karmasakshi.tenant.model import Tenant
from karmasakshi.tenant.org_id import validate_canonical_org_id
from karmasakshi.tenant.registry import TenantRegistry


@dataclass
class MultiTenantControlPlane:
    registry: TenantRegistry = field(default_factory=TenantRegistry)
    data_root: Path | None = None
    _states: dict[str, ApiState] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock)

    def create_tenant(self, tenant: Tenant) -> Tenant:
        with self._lock:
            if self.registry.get(tenant.tenant_id) is not None:
                raise TenantIsolationError(
                    f"tenant {tenant.tenant_id!r} already exists (fail closed)"
                )
            self.registry.register(tenant)
            self._states[tenant.tenant_id] = self._build_state(tenant.tenant_id)
            return tenant

    def get_state(self, tenant_id: str) -> ApiState:
        require_active_tenant(self.registry, tenant_id)
        with self._lock:
            state = self._states.get(tenant_id)
            if state is None:
                raise TenantIsolationError(
                    f"no control-plane state for tenant {tenant_id!r} (fail closed)"
                )
            return state

    def reject_cross_tenant(self, *, acting_tenant_id: str, resource_tenant_id: str) -> None:
        require_active_tenant(self.registry, acting_tenant_id)
        if acting_tenant_id != resource_tenant_id:
            raise TenantIsolationError(
                f"Organization/tenant {acting_tenant_id!r} cannot access "
                f"tenant {resource_tenant_id!r} data (fail closed)"
            )

    def _build_state(self, tenant_id: str) -> ApiState:
        # RA-001: this is the storage boundary where tenant_id becomes a
        # filesystem path. Re-validate here even though `Tenant.__post_init__`
        # already did -- this method must independently prove containment
        # and must never trust that a caller upheld the model invariant.
        validate_canonical_org_id(tenant_id)
        root = (self.data_root or Path.cwd() / ".karmasakshi-tenants").resolve()
        tenant_dir = (root / tenant_id).resolve()
        if tenant_dir == root or not tenant_dir.is_relative_to(root):
            raise TenantIsolationError(
                "resolved tenant path escapes the configured data root (fail closed)"
            )
        tenant_dir.mkdir(parents=True, exist_ok=True)
        state = build_default_state(tenant_dir)
        state.engine.context.tenant_id = tenant_id
        return state


__all__ = ["MultiTenantControlPlane"]
