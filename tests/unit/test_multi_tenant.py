"""Tests for multi-tenant control plane (Phase 19)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from karmasakshi.audit.journal import AuditJournal
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring
from karmasakshi.engine.context import EngineContext
from karmasakshi.engine.core import KarmaSakshiEngine
from karmasakshi.errors import TenantIsolationError, UnknownTenantError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.intelligence.policy import build_policy_bundle
from karmasakshi.policy.sealing import seal_policy_bundle
from karmasakshi.stores.memory import InMemoryGrantStore
from karmasakshi.tenant import (
    Tenant,
    TenantRegistry,
    assert_tenant_match,
    require_active_tenant,
)
from karmasakshi.tenant.control_plane import MultiTenantControlPlane

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_unknown_and_suspended_tenant_fail_closed():
    registry = TenantRegistry()
    registry.register(Tenant(tenant_id="org-a", display_name="Org A", created_at=NOW))
    with pytest.raises(UnknownTenantError):
        registry.require("org-missing")
    registry.suspend("org-a")
    with pytest.raises(TenantIsolationError, match="suspended"):
        registry.require("org-a")


def test_assert_tenant_match_fail_closed_on_uncertainty():
    assert_tenant_match(expected=None, presented=None)
    assert_tenant_match(expected="a", presented="a")
    with pytest.raises(TenantIsolationError, match="uncertainty"):
        assert_tenant_match(expected="a", presented=None)
    with pytest.raises(TenantIsolationError, match="cross-tenant"):
        assert_tenant_match(expected="a", presented="b")


def test_control_plane_isolates_states(tmp_path: Path):
    plane = MultiTenantControlPlane(data_root=tmp_path)
    plane.create_tenant(Tenant(tenant_id="org-a", display_name="A", created_at=NOW))
    plane.create_tenant(Tenant(tenant_id="org-b", display_name="B", created_at=NOW))
    state_a = plane.get_state("org-a")
    state_b = plane.get_state("org-b")
    assert state_a is not state_b
    assert state_a.engine.context.tenant_id == "org-a"
    assert state_b.engine.context.tenant_id == "org-b"
    with pytest.raises(TenantIsolationError, match="cannot access"):
        plane.reject_cross_tenant(acting_tenant_id="org-a", resource_tenant_id="org-b")
    plane.reject_cross_tenant(acting_tenant_id="org-a", resource_tenant_id="org-a")


def test_cross_tenant_policy_bundle_blocked_at_authorize(
    manifest_factory, issuer_signing_key, human_principal, agent_principal
):
    from karmasakshi.intelligence.policy import IntelligencePolicy
    from karmasakshi.state_machine.states import LifecycleState

    clock = FixedClock(NOW)
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=Keyring([issuer_signing_key.verification_key()]),
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=clock),
            clock=clock,
            tenant_id="org-a",
        )
    )
    manifest = manifest_factory()
    engine.seed_lifecycle_state(manifest.manifest_id, LifecycleState.PREPARED)
    sealed = engine.seal(manifest, issuer_signing_key)
    foreign = build_policy_bundle(
        policy=IntelligencePolicy(),
        bundle_id="bundle-foreign",
        bundle_version="1.0",
        issuer=human_principal,
        created_at=NOW,
        effective_from=NOW,
        tenant_id="org-b",
    )
    sealed_policy = seal_policy_bundle(foreign, issuer_signing_key, clock=clock)
    with pytest.raises(TenantIsolationError, match="cross-tenant"):
        engine.authorize(
            sealed,
            issuer=human_principal,
            subject=agent_principal,
            audience=("payment.simulator",),
            allowed_effect_types=(manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=NOW,
            expires_at=NOW + timedelta(hours=1),
            signing_key=issuer_signing_key,
            policy_bundle=sealed_policy,
        )


def test_matching_tenant_policy_allows_authorize(
    manifest_factory, issuer_signing_key, human_principal, agent_principal
):
    from karmasakshi.intelligence.policy import IntelligencePolicy
    from karmasakshi.state_machine.states import LifecycleState

    clock = FixedClock(NOW)
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=Keyring([issuer_signing_key.verification_key()]),
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=clock),
            clock=clock,
            tenant_id="org-a",
        )
    )
    manifest = manifest_factory()
    engine.seed_lifecycle_state(manifest.manifest_id, LifecycleState.PREPARED)
    sealed = engine.seal(manifest, issuer_signing_key)
    bundle = build_policy_bundle(
        policy=IntelligencePolicy(),
        bundle_id="bundle-a",
        bundle_version="1.0",
        issuer=human_principal,
        created_at=NOW,
        effective_from=NOW,
        tenant_id="org-a",
    )
    sealed_policy = seal_policy_bundle(bundle, issuer_signing_key, clock=clock)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=("payment.simulator",),
        allowed_effect_types=(manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=NOW,
        expires_at=NOW + timedelta(hours=1),
        signing_key=issuer_signing_key,
        policy_bundle=sealed_policy,
    )
    assert grant.policy_bundle_hash == sealed_policy.seal.bundle_hash


def test_require_active_tenant_needs_registry():
    with pytest.raises(TenantIsolationError, match="registry is not configured"):
        require_active_tenant(None, "org-a")
    with pytest.raises(TenantIsolationError, match="tenant_id is required"):
        require_active_tenant(TenantRegistry(), None)


def test_tenant_model_and_registry_edges(tmp_path: Path):
    with pytest.raises(ValueError):
        Tenant(tenant_id="", display_name="x")
    with pytest.raises(ValueError):
        Tenant(tenant_id="ok", display_name="")
    with pytest.raises(ValueError):
        Tenant(tenant_id="ok", display_name="x", status="nope")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Tenant(
            tenant_id="ok",
            display_name="x",
            created_at=datetime(2026, 1, 1, 12, 0, 0),
        )
    t = Tenant(tenant_id="org-z", display_name="Z", created_at=NOW)
    assert t.canonical_hash().startswith("sha256:")
    registry = TenantRegistry()
    registry.register(t)
    assert len(registry) == 1
    assert registry.list_tenants()[0].tenant_id == "org-z"
    with pytest.raises(UnknownTenantError):
        registry.suspend("missing")
    plane = MultiTenantControlPlane(data_root=tmp_path)
    plane.create_tenant(Tenant(tenant_id="org-dup", display_name="D", created_at=NOW))
    with pytest.raises(TenantIsolationError, match="already exists"):
        plane.create_tenant(Tenant(tenant_id="org-dup", display_name="D2", created_at=NOW))


def test_get_state_unchecked_bypasses_active_gate_but_not_existence(tmp_path: Path):
    plane = MultiTenantControlPlane(data_root=tmp_path)
    with pytest.raises(TenantIsolationError, match="no control-plane state"):
        plane.get_state_unchecked("never-registered")

    plane.create_tenant(Tenant(tenant_id="org-a", display_name="A", created_at=NOW))
    plane.registry.suspend("org-a")
    # get_state() fails closed on a suspended tenant (the request-serving path)...
    with pytest.raises(TenantIsolationError, match="suspended"):
        plane.get_state("org-a")
    # ...but get_state_unchecked() still returns the built runtime, for
    # internal maintenance use (RA-002 follow-up rehydration).
    assert plane.get_state_unchecked("org-a") is plane.get_state_unchecked("org-a")
