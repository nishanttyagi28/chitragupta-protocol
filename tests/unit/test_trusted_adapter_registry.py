"""Tests for the trusted adapter registry (Phase 17)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from karmasakshi.adapters.payment_simulator import (
    PaymentRequest,
    PaymentSimulator,
    PaymentSimulatorAdapter,
)
from karmasakshi.adapters.registry import (
    AdapterCapability,
    RegistryEntry,
    TrustedAdapterRegistry,
    build_reference_registry,
    facts_from_capability,
    reference_adapter_capabilities,
)
from karmasakshi.audit.journal import AuditJournal
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.engine.context import EngineContext
from karmasakshi.engine.core import KarmaSakshiEngine
from karmasakshi.errors import UntrustedAdapterError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.intelligence.facts import AssessmentFacts
from karmasakshi.state_machine.states import LifecycleState
from karmasakshi.stores.memory import InMemoryGrantStore

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def payment_simulator() -> PaymentSimulator:
    sim = PaymentSimulator()
    sim.fund_account("acct-src", 1_000_000)
    return sim


def _payment_request(actor: Principal, principal: Principal, *, idem: str) -> PaymentRequest:
    return PaymentRequest(
        actor=actor,
        principal=principal,
        source_account="acct-src",
        beneficiary="acct-dst",
        amount_minor_units=100,
        currency="INR",
        reference="ref-1",
        idempotency_key=idem,
        ttl_seconds=300,
    )


def test_reference_registry_trusts_shipped_adapters():
    registry = build_reference_registry()
    assert len(registry) == 3
    for cap in reference_adapter_capabilities():
        assert registry.is_trusted(cap.adapter_id, cap.adapter_version)
        got = registry.require(cap.adapter_id, cap.adapter_version)
        assert got.canonical_hash() == cap.canonical_hash()


def test_unknown_adapter_fails_closed():
    registry = build_reference_registry()
    with pytest.raises(UntrustedAdapterError, match="not on the trusted"):
        registry.require("evil.adapter", "1.0.0")


def test_version_pin_is_exact():
    registry = build_reference_registry()
    with pytest.raises(UntrustedAdapterError):
        registry.require("payment.simulator", "1.0.1")
    with pytest.raises(UntrustedAdapterError):
        registry.require("payment.simulator", "2.0.0")


def test_revoked_adapter_fails_closed():
    registry = build_reference_registry()
    registry.revoke(
        "payment.simulator",
        "1.0.0",
        revoked_at=NOW,
        reason="operator recall",
    )
    with pytest.raises(UntrustedAdapterError, match="revoked"):
        registry.require("payment.simulator", "1.0.0")
    with pytest.raises(UntrustedAdapterError, match="cannot revoke unknown"):
        registry.revoke("missing.adapter", "1.0.0", revoked_at=NOW)


def test_undeclared_effect_type_fails_closed():
    registry = build_reference_registry()
    with pytest.raises(UntrustedAdapterError, match="not declared"):
        registry.require_effect("payment.simulator", "1.0.0", "payment.wire_fraud")


def test_environment_allow_list():
    registry = TrustedAdapterRegistry(
        [
            AdapterCapability(
                adapter_id="payment.simulator",
                adapter_version="1.0.0",
                supported_effect_types=("payment.transfer",),
                environments=("prod",),
            )
        ]
    )
    registry.require_environment("payment.simulator", "1.0.0", "prod")
    with pytest.raises(UntrustedAdapterError, match="environment"):
        registry.require_environment("payment.simulator", "1.0.0", "dev")


def test_facts_from_capability_merges_explicit_declarations():
    cap = AdapterCapability(
        adapter_id="payment.simulator",
        adapter_version="1.0.0",
        supported_effect_types=("payment.transfer",),
        provider_idempotent=True,
        compensation_feasible=False,
    )
    facts = facts_from_capability(cap, base=AssessmentFacts(delegation_depth=2))
    assert facts.delegation_depth == 2
    assert facts.provider_idempotent is True
    assert facts.compensation_feasible is False


def test_capability_rejects_empty_effect_types():
    with pytest.raises(ValueError, match="non-empty"):
        AdapterCapability(
            adapter_id="x",
            adapter_version="1.0.0",
            supported_effect_types=(),
        )


def test_capability_and_entry_validation_edges():
    with pytest.raises(ValueError, match="adapter_id"):
        AdapterCapability(
            adapter_id="",
            adapter_version="1.0.0",
            supported_effect_types=("a",),
        )
    with pytest.raises(ValueError, match="adapter_version"):
        AdapterCapability(
            adapter_id="x",
            adapter_version="",
            supported_effect_types=("a",),
        )
    with pytest.raises(ValueError, match="supported_effect_types exceeds"):
        AdapterCapability(
            adapter_id="x",
            adapter_version="1.0.0",
            supported_effect_types=tuple(f"e{i}" for i in range(65)),
        )
    with pytest.raises(ValueError, match="supported_effect_types entries"):
        AdapterCapability(
            adapter_id="x",
            adapter_version="1.0.0",
            supported_effect_types=("",),
        )
    with pytest.raises(ValueError, match="environments exceeds"):
        AdapterCapability(
            adapter_id="x",
            adapter_version="1.0.0",
            supported_effect_types=("a",),
            environments=tuple(f"env{i}" for i in range(33)),
        )
    with pytest.raises(ValueError, match="environments entries"):
        AdapterCapability(
            adapter_id="x",
            adapter_version="1.0.0",
            supported_effect_types=("a",),
            environments=("",),
        )
    with pytest.raises(ValueError, match="description"):
        AdapterCapability(
            adapter_id="x",
            adapter_version="1.0.0",
            supported_effect_types=("a",),
            description="x" * 513,
        )
    cap = AdapterCapability(
        adapter_id="payment.simulator",
        adapter_version="1.0.0",
        supported_effect_types=("payment.transfer",),
    )
    assert cap.identity.adapter_id == "payment.simulator"
    with pytest.raises(ValueError, match="revoked_at"):
        RegistryEntry(capability=cap, revoked=True, revoked_at=None)
    with pytest.raises(ValueError, match="revoke_reason"):
        RegistryEntry(
            capability=cap,
            revoked=True,
            revoked_at=NOW,
            revoke_reason="x" * 257,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        RegistryEntry(
            capability=cap,
            revoked=True,
            revoked_at=datetime(2026, 1, 1, 12, 0, 0),
        )


def test_list_entries_and_require_adapter(payment_simulator):
    registry = build_reference_registry()
    entries = registry.list_entries()
    assert len(entries) == 3
    assert entries[0].capability.adapter_id <= entries[-1].capability.adapter_id
    adapter = PaymentSimulatorAdapter(payment_simulator)
    assert registry.require_adapter(adapter).adapter_id == "payment.simulator"


def test_prepare_and_commit_fail_closed_for_untrusted_adapter(
    payment_simulator, human_principal, agent_principal
):
    clock = FixedClock(NOW)
    key = generate_signing_key("issuer")
    registry = TrustedAdapterRegistry()  # empty allow-list
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=Keyring([key.verification_key()]),
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=clock),
            clock=clock,
            adapter_registry=registry,
        )
    )
    adapter = PaymentSimulatorAdapter(payment_simulator)
    request = _payment_request(agent_principal, human_principal, idem="idem-untrusted-1")
    with pytest.raises(UntrustedAdapterError):
        engine.prepare(adapter, request, context=None)

    registry.register(
        AdapterCapability(
            adapter_id=adapter.adapter_id,
            adapter_version=adapter.adapter_version,
            supported_effect_types=("payment.transfer",),
        )
    )
    manifest = engine.prepare(adapter, request, context=None)
    sealed = engine.seal(manifest, key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(adapter.adapter_id,),
        allowed_effect_types=(manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=NOW,
        expires_at=NOW + timedelta(hours=1),
        signing_key=key,
    )
    registry.revoke(adapter.adapter_id, adapter.adapter_version, revoked_at=NOW, reason="recall")
    with pytest.raises(UntrustedAdapterError, match="revoked"):
        engine.commit(sealed, grant, adapter, context=None)


def test_commit_rejects_effect_type_outside_capability(
    payment_simulator, human_principal, agent_principal, manifest_factory, issuer_signing_key
):
    clock = FixedClock(NOW)
    registry = TrustedAdapterRegistry(
        [
            AdapterCapability(
                adapter_id="payment.simulator",
                adapter_version="1.0.0",
                supported_effect_types=("payment.transfer",),
            )
        ]
    )
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=Keyring([issuer_signing_key.verification_key()]),
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=clock),
            clock=clock,
            adapter_registry=registry,
        )
    )
    manifest = manifest_factory(
        effect_type="payment.unauthorized_type",
        actor=agent_principal,
        principal=human_principal,
    )
    engine.seed_lifecycle_state(manifest.manifest_id, LifecycleState.PREPARED)
    sealed = engine.seal(manifest, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=("payment.simulator",),
        allowed_effect_types=("payment.unauthorized_type",),
        scope=ScopeConstraints(),
        not_before=NOW,
        expires_at=NOW + timedelta(hours=1),
        signing_key=issuer_signing_key,
    )
    adapter = PaymentSimulatorAdapter(payment_simulator)
    with pytest.raises(UntrustedAdapterError, match="not declared"):
        engine.commit(sealed, grant, adapter, context=None)


def test_no_registry_preserves_legacy_behavior(payment_simulator, human_principal, agent_principal):
    clock = FixedClock(NOW)
    key = generate_signing_key("issuer")
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=Keyring([key.verification_key()]),
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=clock),
            clock=clock,
            adapter_registry=None,
        )
    )
    adapter = PaymentSimulatorAdapter(payment_simulator)
    request = _payment_request(agent_principal, human_principal, idem="idem-legacy-reg-1")
    manifest = engine.prepare(adapter, request, context=None)
    sealed = engine.seal(manifest, key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(adapter.adapter_id,),
        allowed_effect_types=(manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=NOW,
        expires_at=NOW + timedelta(hours=1),
        signing_key=key,
    )
    result = engine.commit(sealed, grant, adapter, context=None)
    assert result.success is True
