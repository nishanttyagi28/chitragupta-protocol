"""RA-002: unit tests for `rehydrate_tenant_registrations` directly, plus
suspended-org and idempotency cases the end-to-end restart tests in
`tests/integration/test_gateway_restart.py` don't exercise."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from pathlib import Path

from karmasakshi.gateway.api import GatewayApiState, rehydrate_tenant_registrations
from karmasakshi.gateway.models import OrganizationStatus
from karmasakshi.gateway.store import GatewayStore
from karmasakshi.tenant.control_plane import MultiTenantControlPlane


def _fresh_gateway_state(tmp_path: Path) -> GatewayApiState:
    return GatewayApiState(
        store=GatewayStore(tmp_path / "gateway.db"),
        control_plane=MultiTenantControlPlane(data_root=tmp_path / "tenants"),
    )


def test_rehydrate_registers_every_durable_organization(tmp_path: Path) -> None:
    gw = _fresh_gateway_state(tmp_path)
    gw.store.create_organization("acme", "Acme Corp")
    gw.store.create_organization("beta", "Beta Inc")
    assert gw.control_plane.registry.get("acme") is None

    rehydrate_tenant_registrations(gw)

    assert gw.control_plane.registry.get("acme") is not None
    assert gw.control_plane.registry.get("beta") is not None
    # The runtime is actually usable, not just registered.
    gw.control_plane.get_state("acme")
    gw.control_plane.get_state("beta")


def test_rehydrate_registers_suspended_orgs_as_suspended(tmp_path: Path) -> None:
    gw = _fresh_gateway_state(tmp_path)
    gw.store.create_organization("acme", "Acme Corp")
    gw.store.set_organization_status("acme", OrganizationStatus.SUSPENDED)

    rehydrate_tenant_registrations(gw)

    tenant = gw.control_plane.registry.get("acme")
    assert tenant is not None
    assert tenant.status == "suspended"


def test_rehydrate_is_idempotent(tmp_path: Path) -> None:
    gw = _fresh_gateway_state(tmp_path)
    gw.store.create_organization("acme", "Acme Corp")

    rehydrate_tenant_registrations(gw)
    rehydrate_tenant_registrations(gw)  # must not raise "already exists"

    assert gw.control_plane.registry.get("acme") is not None


def test_rehydrate_with_no_organizations_is_a_no_op(tmp_path: Path) -> None:
    gw = _fresh_gateway_state(tmp_path)
    rehydrate_tenant_registrations(gw)
    assert len(gw.control_plane.registry) == 0
