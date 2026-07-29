"""Tenant isolation enforcement helpers (Phase 19)."""

from __future__ import annotations

from karmasakshi.errors import TenantIsolationError
from karmasakshi.tenant.model import Tenant
from karmasakshi.tenant.registry import TenantRegistry


def require_active_tenant(registry: TenantRegistry | None, tenant_id: str | None) -> Tenant:
    """Resolve an active tenant or fail closed.

    A missing registry or missing tenant_id is treated as uncertainty when
    either is partially present — both must be configured together.
    """
    if registry is None:
        raise TenantIsolationError(
            "tenant registry is not configured; refuse tenant-scoped operation (fail closed)"
        )
    if tenant_id is None or not tenant_id.strip():
        raise TenantIsolationError(
            "tenant_id is required for this operation; refuse to invent a tenant (fail closed)"
        )
    return registry.require(tenant_id.strip())


def assert_tenant_match(
    *,
    expected: str | None,
    presented: str | None,
    field: str = "tenant_id",
) -> None:
    """Fail closed when either side declares a tenant and they disagree.

    Rules (deterministic):
    - Both ``None``: OK (legacy single-tenant / unset).
    - One set, other ``None``: uncertainty → fail closed.
    - Both set and unequal: cross-tenant → fail closed.
    - Both set and equal: OK.
    """
    if expected is None and presented is None:
        return
    if expected is None or presented is None:
        raise TenantIsolationError(
            f"{field} mismatch under tenant uncertainty "
            f"(expected={expected!r}, presented={presented!r}); fail closed"
        )
    if expected != presented:
        raise TenantIsolationError(
            f"cross-tenant access rejected: expected {field}={expected!r}, "
            f"presented {presented!r} (fail closed)"
        )


def bind_engine_and_policy_tenant(
    *,
    engine_tenant_id: str | None,
    policy_tenant_id: str | None,
) -> None:
    """Enforce policy-bundle tenant binding against the engine tenant context."""
    assert_tenant_match(
        expected=engine_tenant_id,
        presented=policy_tenant_id,
        field="policy_bundle.tenant_id",
    )


__all__ = [
    "assert_tenant_match",
    "bind_engine_and_policy_tenant",
    "require_active_tenant",
]
