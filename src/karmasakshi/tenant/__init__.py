"""Multi-tenant control plane (extreme-v2 Phase 19).

Import ``MultiTenantControlPlane`` from
``karmasakshi.tenant.control_plane`` to avoid a circular import with the
API/engine packages.
"""

from __future__ import annotations

from karmasakshi.tenant.enforce import (
    assert_tenant_match,
    bind_engine_and_policy_tenant,
    require_active_tenant,
)
from karmasakshi.tenant.model import Tenant, TenantStatus
from karmasakshi.tenant.registry import TenantRegistry

__all__ = [
    "Tenant",
    "TenantRegistry",
    "TenantStatus",
    "assert_tenant_match",
    "bind_engine_and_policy_tenant",
    "require_active_tenant",
]
