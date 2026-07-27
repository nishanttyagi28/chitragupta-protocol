from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from chitragupta.domain import (
    AdapterIdentity,
    BlastRadiusClassification,
    EffectManifest,
    MonetaryAmount,
    Principal,
    PrincipalType,
    ReversibilityClassification,
    RiskClassification,
    StateFingerprint,
    StateFingerprintKind,
)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def agent_principal() -> Principal:
    return Principal(principal_id="agent-1", principal_type=PrincipalType.AGENT, display_name="Agent One")


@pytest.fixture
def human_principal() -> Principal:
    return Principal(principal_id="user-1", principal_type=PrincipalType.HUMAN, display_name="Alice")


@pytest.fixture
def service_principal() -> Principal:
    return Principal(principal_id="policy-engine", principal_type=PrincipalType.SERVICE)


@pytest.fixture
def adapter_identity() -> AdapterIdentity:
    return AdapterIdentity(adapter_id="payment.simulator", adapter_version="1.0.0")


def make_manifest(
    *,
    now: datetime,
    actor: Principal,
    principal: Principal,
    adapter: AdapterIdentity,
    effect_type: str = "payment.transfer",
    target_resource: str = "payment:beneficiary/X",
    parameters: dict | None = None,
    amount_minor_units: int = 150000,
    currency: str = "INR",
    ttl_seconds: int = 300,
    nonce: str = "nonce-fixed-1",
    idempotency_key: str = "idem-fixed-1",
    manifest_id: str | None = None,
    state_fingerprint: StateFingerprint | None = None,
    parent_manifest_id: str | None = None,
) -> EffectManifest:
    return EffectManifest(
        manifest_id=manifest_id or "11111111-1111-4111-8111-111111111111",
        effect_type=effect_type,
        actor=actor,
        principal=principal,
        adapter=adapter,
        target_resource=target_resource,
        parameters=parameters if parameters is not None else {"amount": amount_minor_units, "currency": currency},
        state_fingerprint=state_fingerprint,
        risk=RiskClassification.HIGH,
        reversibility=ReversibilityClassification.COMPENSATABLE,
        blast_radius=BlastRadiusClassification.SINGLE_RESOURCE,
        estimated_cost=MonetaryAmount(currency=currency, minor_units=amount_minor_units),
        idempotency_key=idempotency_key,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        nonce=nonce,
        parent_manifest_id=parent_manifest_id,
    )


@pytest.fixture
def manifest_factory(now, agent_principal, human_principal, adapter_identity):
    def _factory(**kwargs):
        kwargs.setdefault("now", now)
        kwargs.setdefault("actor", agent_principal)
        kwargs.setdefault("principal", human_principal)
        kwargs.setdefault("adapter", adapter_identity)
        return make_manifest(**kwargs)

    return _factory
