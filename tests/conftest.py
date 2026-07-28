from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from karmasakshi.adapters.base import (
    CommitResult,
    CompensationResult,
    OutcomeProof,
    PreconditionResult,
)
from karmasakshi.audit.journal import AuditJournal
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, SigningKey, generate_signing_key
from karmasakshi.domain import (
    AdapterIdentity,
    BlastRadiusClassification,
    EffectManifest,
    MonetaryAmount,
    Principal,
    PrincipalType,
    ReversibilityClassification,
    RiskClassification,
    StateFingerprint,
)
from karmasakshi.engine import EngineContext, KarmaSakshiEngine
from karmasakshi.stores.memory import InMemoryGrantStore


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def agent_principal() -> Principal:
    return Principal(
        principal_id="agent-1", principal_type=PrincipalType.AGENT, display_name="Agent One"
    )


@pytest.fixture
def human_principal() -> Principal:
    return Principal(
        principal_id="user-1", principal_type=PrincipalType.HUMAN, display_name="Alice"
    )


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
        parameters=parameters
        if parameters is not None
        else {"amount": amount_minor_units, "currency": currency},
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
def issuer_signing_key() -> SigningKey:
    return generate_signing_key("dev-issuer-1")


@pytest.fixture
def other_signing_key() -> SigningKey:
    return generate_signing_key("dev-issuer-2")


@pytest.fixture
def keyring(issuer_signing_key) -> Keyring:
    return Keyring([issuer_signing_key.verification_key()])


@pytest.fixture
def manifest_factory(now, agent_principal, human_principal, adapter_identity):
    def _factory(**kwargs):
        kwargs.setdefault("now", now)
        kwargs.setdefault("actor", agent_principal)
        kwargs.setdefault("principal", human_principal)
        kwargs.setdefault("adapter", adapter_identity)
        return make_manifest(**kwargs)

    return _factory


@dataclass
class FakeAdapterState:
    committed: list[dict[str, str]] = field(default_factory=list)
    precondition_ok: bool = True
    precondition_reason: str = "external state changed since prepare"
    fail_commit: bool = False
    raise_on_commit: bool = False
    matched_expected: bool = True
    compensation_attempted: bool = True
    compensation_succeeded: bool = True
    # Simulates the adapter's own external system of record, keyed by
    # idempotency_key -- independent of anything karmasakshi's grant store
    # tracks. Used to test ambiguous-outcome crash recovery.
    external_effects: dict[str, str] = field(default_factory=dict)


class FakeAdapter:
    """A minimal in-memory adapter used only to exercise the engine in tests.

    Real adapters (sqlite/email/payment) are implemented in
    ``karmasakshi.adapters`` for phase 8; this fake exists purely so engine
    orchestration can be unit-tested independent of any real side effect.
    """

    adapter_id = "payment.simulator"
    adapter_version = "1.0.0"

    def __init__(self, state: FakeAdapterState, clock: FixedClock) -> None:
        self.state = state
        self.clock = clock

    def prepare(self, request: EffectManifest, context: Any) -> EffectManifest:
        return request

    def validate_preconditions(self, manifest: EffectManifest, context: Any) -> PreconditionResult:
        if self.state.precondition_ok:
            return PreconditionResult(satisfied=True)
        return PreconditionResult(satisfied=False, reason=self.state.precondition_reason)

    def commit(self, manifest: EffectManifest, grant: Any, context: Any) -> CommitResult:
        if self.state.raise_on_commit:
            raise RuntimeError("simulated adapter crash")
        if self.state.fail_commit:
            return CommitResult(
                success=False, idempotency_key=manifest.idempotency_key, detail="simulated failure"
            )
        ref = f"ref-{len(self.state.committed) + 1}"
        self.state.committed.append({"manifest_id": manifest.manifest_id, "ref": ref})
        self.state.external_effects[manifest.idempotency_key] = ref
        return CommitResult(
            success=True, idempotency_key=manifest.idempotency_key, provider_reference=ref
        )

    def verify(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> OutcomeProof:
        if commit_result.provider_reference is None:
            # Ambiguous-outcome recovery probe: independently check external
            # state by idempotency_key rather than trusting commit_result.
            ref = self.state.external_effects.get(manifest.idempotency_key)
            if ref is None:
                return OutcomeProof(
                    matched_expected=False, observed_at=self.clock.now(), detail="no evidence found"
                )
            return OutcomeProof(
                matched_expected=True,
                observed_at=self.clock.now(),
                observed_after_state_digest=ref,
                detail="evidence found in external system of record",
            )
        return OutcomeProof(
            matched_expected=self.state.matched_expected, observed_at=self.clock.now()
        )

    def compensate(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> CompensationResult:
        return CompensationResult(
            attempted=self.state.compensation_attempted, succeeded=self.state.compensation_succeeded
        )


@pytest.fixture
def fake_adapter_state() -> FakeAdapterState:
    return FakeAdapterState()


@pytest.fixture
def fixed_clock(now) -> FixedClock:
    return FixedClock(now)


@pytest.fixture
def fake_adapter(fake_adapter_state, fixed_clock) -> FakeAdapter:
    return FakeAdapter(fake_adapter_state, fixed_clock)


@pytest.fixture
def engine_factory(keyring, fixed_clock):
    def _factory(*, grant_store=None):
        ctx = EngineContext(
            keyring=keyring,
            grant_store=grant_store or InMemoryGrantStore(),
            audit=AuditJournal(clock=fixed_clock),
            clock=fixed_clock,
        )
        return KarmaSakshiEngine(ctx)

    return _factory
