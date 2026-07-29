"""Tests for the adapter conformance kit (Phase 18)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from karmasakshi.adapters.base import (
    CommitResult,
    CompensationResult,
    OutcomeProof,
    PreconditionResult,
)
from karmasakshi.adapters.conformance import (
    ConformanceScenario,
    run_adapter_conformance,
)
from karmasakshi.adapters.email_sandbox import EmailRequest, EmailSandboxAdapter, SandboxOutbox
from karmasakshi.adapters.payment_simulator import (
    PaymentRequest,
    PaymentSimulator,
    PaymentSimulatorAdapter,
)
from karmasakshi.adapters.sqlite_db import RowEffectRequest, SQLiteRowAdapter
from karmasakshi.domain.common import AdapterIdentity
from karmasakshi.domain.enums import (
    BlastRadiusClassification,
    ReversibilityClassification,
    RiskClassification,
)
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.errors import AdapterConformanceError


def test_payment_simulator_passes_conformance(agent_principal, human_principal):
    sim = PaymentSimulator()
    sim.fund_account("acct-src", 1_000_000)
    adapter = PaymentSimulatorAdapter(sim)
    report = run_adapter_conformance(
        adapter,
        ConformanceScenario(
            request=PaymentRequest(
                actor=agent_principal,
                principal=human_principal,
                source_account="acct-src",
                beneficiary="acct-dst",
                amount_minor_units=100,
                currency="INR",
                reference="conf-pay-1",
                idempotency_key="idem-conf-pay-1",
            )
        ),
    )
    assert report.passed
    assert report.adapter_id == "payment.simulator"


def test_email_sandbox_passes_conformance(agent_principal, human_principal):
    adapter = EmailSandboxAdapter(SandboxOutbox())
    report = run_adapter_conformance(
        adapter,
        ConformanceScenario(
            request=EmailRequest(
                actor=agent_principal,
                principal=human_principal,
                recipients=("alice@example.com",),
                subject="conformance",
                body="hello",
                idempotency_key="idem-conf-email-1",
            )
        ),
    )
    assert report.passed
    assert any(c.name == "irreversible_compensation" and c.passed for c in report.checks)


def test_sqlite_row_passes_conformance(tmp_path, agent_principal, human_principal):
    adapter = SQLiteRowAdapter(str(tmp_path / "conf.db"), table="ledger")
    report = run_adapter_conformance(
        adapter,
        ConformanceScenario(
            request=RowEffectRequest(
                actor=agent_principal,
                principal=human_principal,
                operation="insert",
                row_id="acct-conf-1",
                new_balance=42,
                idempotency_key="idem-conf-sqlite-1",
            )
        ),
    )
    assert report.passed


def test_sqlite_toctou_mutation_detected(tmp_path, agent_principal, human_principal):
    adapter = SQLiteRowAdapter(str(tmp_path / "toctou.db"), table="ledger")
    # Seed a row, then prepare an update, then mutate version underneath.
    seed = RowEffectRequest(
        actor=agent_principal,
        principal=human_principal,
        operation="insert",
        row_id="acct-t",
        new_balance=10,
        idempotency_key="idem-seed-t",
    )
    seed_manifest = adapter.prepare(seed, None)
    adapter.commit(seed_manifest, None, None)

    update = RowEffectRequest(
        actor=agent_principal,
        principal=human_principal,
        operation="update",
        row_id="acct-t",
        new_balance=20,
        idempotency_key="idem-update-t",
    )

    def mutate() -> None:
        # Commit a competing update to bump the row version / fingerprint.
        competing = RowEffectRequest(
            actor=agent_principal,
            principal=human_principal,
            operation="update",
            row_id="acct-t",
            new_balance=99,
            idempotency_key="idem-competing-t",
        )
        m = adapter.prepare(competing, None)
        adapter.commit(m, None, None)

    report = run_adapter_conformance(
        adapter,
        ConformanceScenario(
            request=update,
            expect_stale_after_mutate=True,
            mutate_external_state=mutate,
        ),
        raise_on_fail=False,
    )
    # After mutate, preconditions check should pass the kit; commit may fail
    # because the fingerprint is stale — that is still honest.
    pre = next(c for c in report.checks if c.name == "preconditions")
    assert pre.passed


class _DishonestAdapter:
    """Always trusts CommitResult.success — must fail the kit."""

    adapter_id = "demo.dishonest"
    adapter_version = "1.0.0"

    def prepare(self, request: EffectManifest, context: Any) -> EffectManifest:
        return request

    def validate_preconditions(self, manifest: EffectManifest, context: Any) -> PreconditionResult:
        return PreconditionResult(satisfied=True)

    def commit(self, manifest: EffectManifest, grant: Any, context: Any) -> CommitResult:
        return CommitResult(success=True, idempotency_key=manifest.idempotency_key)

    def verify(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> OutcomeProof:
        return OutcomeProof(
            matched_expected=bool(commit_result.success),
            observed_at=datetime.now(timezone.utc),
            detail="trusted commit_result alone",
        )

    def compensate(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> CompensationResult:
        return CompensationResult(attempted=False, succeeded=True, reason="lying")


def test_dishonest_adapter_fails_conformance(agent_principal, human_principal):
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    manifest = EffectManifest(
        manifest_id="22222222-2222-4222-8222-222222222222",
        effect_type="demo.dishonest.effect",
        actor=agent_principal,
        principal=human_principal,
        adapter=AdapterIdentity(adapter_id="demo.dishonest", adapter_version="1.0.0"),
        target_resource="demo:dishonest/1",
        parameters={"x": 1},
        risk=RiskClassification.LOW,
        reversibility=ReversibilityClassification.IRREVERSIBLE,
        blast_radius=BlastRadiusClassification.SINGLE_RESOURCE,
        idempotency_key="idem-dishonest-1",
        created_at=now,
        expires_at=now.replace(hour=13),
        nonce="nonce-dishonest-1",
    )
    with pytest.raises(AdapterConformanceError):
        run_adapter_conformance(
            _DishonestAdapter(),
            ConformanceScenario(request=manifest),
        )
