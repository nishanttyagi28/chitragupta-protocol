"""``karmasakshi demo --all``: a deterministic, readable walkthrough of every
required security scenario against the real engine and real reference
adapters (no mocks standing in for the protocol itself).
"""

from __future__ import annotations

import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any

import typer

from karmasakshi.adapters.base import CommitResult, OutcomeProof, PreconditionResult
from karmasakshi.adapters.email_sandbox import EmailRequest, EmailSandboxAdapter, SandboxOutbox
from karmasakshi.adapters.payment_simulator import (
    PaymentRequest,
    PaymentSimulator,
    PaymentSimulatorAdapter,
)
from karmasakshi.adapters.sqlite_db import RowEffectRequest, SQLiteRowAdapter
from karmasakshi.audit.journal import AuditJournal
from karmasakshi.cli.common import console
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.engine.context import EngineContext
from karmasakshi.engine.core import KarmaSakshiEngine
from karmasakshi.errors import (
    GrantExpiredError,
    GrantRevokedError,
    KarmaSakshiError,
    ManifestTamperedError,
    StaleManifestError,
)
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.integrations.agenteval import export_regression_fixture, write_fixture
from karmasakshi.stores.memory import InMemoryGrantStore

AGENT = Principal(principal_id="agent-1", principal_type=PrincipalType.AGENT)
HUMAN = Principal(principal_id="approver-1", principal_type=PrincipalType.HUMAN)


@dataclass
class DemoContext:
    now: datetime
    clock: FixedClock
    engine: KarmaSakshiEngine
    signing_key: Any
    other_signing_key: Any
    keyring: Keyring
    tmp_dir: Path
    results: list[tuple[str, bool, str]] = field(default_factory=list)

    def record(self, name: str, passed: bool, detail: str) -> None:
        self.results.append((name, passed, detail))
        symbol = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
        console.print(f"{symbol}  {name}: {detail}")


def _build_context() -> DemoContext:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    clock = FixedClock(now)
    signing_key = generate_signing_key("demo-issuer")
    other_signing_key = generate_signing_key("demo-untrusted")
    keyring = Keyring([signing_key.verification_key()])
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=keyring,
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=clock),
            clock=clock,
        )
    )
    tmp_dir = Path(tempfile.mkdtemp(prefix="karmasakshi-demo-"))
    return DemoContext(
        now=now,
        clock=clock,
        engine=engine,
        signing_key=signing_key,
        other_signing_key=other_signing_key,
        keyring=keyring,
        tmp_dir=tmp_dir,
    )


def _authorize(ctx: DemoContext, sealed: Any, adapter: Any, **overrides: Any) -> Any:
    kwargs = {
        "issuer": HUMAN,
        "subject": AGENT,
        "audience": (adapter.adapter_id,),
        "allowed_effect_types": (sealed.manifest.effect_type,),
        "scope": ScopeConstraints(),
        "not_before": ctx.now,
        "expires_at": ctx.now + timedelta(minutes=5),
        "signing_key": ctx.signing_key,
    }
    kwargs.update(overrides)
    return ctx.engine.authorize(sealed, **kwargs)


# --- scenarios ------------------------------------------------------------


def scenario_1_no_valid_grant_is_blocked(ctx: DemoContext) -> None:
    simulator = PaymentSimulator()
    simulator.fund_account("acct-src", 1_000_000)
    adapter = PaymentSimulatorAdapter(simulator)
    request = PaymentRequest(
        actor=AGENT,
        principal=HUMAN,
        source_account="acct-src",
        beneficiary="merchant-A",
        amount_minor_units=1000,
        currency="INR",
        reference="demo-1",
        idempotency_key="demo-idem-1",
    )
    manifest = ctx.engine.prepare(adapter, request, context=None)
    sealed = ctx.engine.seal(manifest, ctx.signing_key)
    # Issue a grant signed by an UNTRUSTED key -- never issued through a trusted authority.
    from karmasakshi.grants.issuer import issue_grant

    bogus_grant = issue_grant(
        grant_id="bogus-grant-1",
        issuer=HUMAN,
        subject=AGENT,
        audience=(adapter.adapter_id,),
        allowed_effect_types=(manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=ctx.now,
        expires_at=ctx.now + timedelta(minutes=5),
        nonce="bogus-nonce-1",
        signing_key=ctx.other_signing_key,
        manifest_hash=sealed.seal.manifest_hash,
    )
    try:
        ctx.engine.commit(sealed, bogus_grant, adapter, context=None)
        ctx.record("1. Action without a valid grant", False, "commit unexpectedly succeeded")
    except KarmaSakshiError as exc:
        ctx.record("1. Action without a valid grant is blocked", True, f"{type(exc).__name__}")


def scenario_2_exact_approved_email_succeeds(ctx: DemoContext) -> tuple[Any, Any, Any, Any]:
    outbox = SandboxOutbox()
    adapter = EmailSandboxAdapter(outbox)
    request = EmailRequest(
        actor=AGENT,
        principal=HUMAN,
        recipients=("alice@example.com",),
        subject="Invoice #42",
        body="Please find your invoice attached.",
        idempotency_key="demo-idem-2",
    )
    manifest = ctx.engine.prepare(adapter, request, context=None)
    sealed = ctx.engine.seal(manifest, ctx.signing_key)
    grant = _authorize(ctx, sealed, adapter)
    result = ctx.engine.commit(sealed, grant, adapter, context=None)
    proof = ctx.engine.verify(sealed.manifest, result, adapter, context=None)
    ok = result.success and proof.matched_expected
    ctx.record(
        "2. Exact approved email succeeds",
        ok,
        f"delivered={result.success}, verified={proof.matched_expected}",
    )
    return outbox, adapter, sealed, grant


def scenario_3_changed_recipient_after_approval_blocked(ctx: DemoContext) -> None:
    outbox = SandboxOutbox()
    adapter = EmailSandboxAdapter(outbox)
    request = EmailRequest(
        actor=AGENT,
        principal=HUMAN,
        recipients=("alice@example.com",),
        subject="Invoice #43",
        body="Body text.",
        idempotency_key="demo-idem-3",
    )
    manifest = ctx.engine.prepare(adapter, request, context=None)
    sealed = ctx.engine.seal(manifest, ctx.signing_key)
    grant = _authorize(ctx, sealed, adapter)

    attacker_request = EmailRequest(
        actor=AGENT,
        principal=HUMAN,
        recipients=("attacker@example.com",),
        subject="Invoice #43",
        body="Body text.",
        idempotency_key="demo-idem-3",
    )
    tampered_manifest = adapter.prepare(attacker_request, context=None)
    tampered_sealed = sealed.model_copy(update={"manifest": tampered_manifest})
    try:
        ctx.engine.commit(tampered_sealed, grant, adapter, context=None)
        ctx.record("3. Changed recipient after approval", False, "commit unexpectedly succeeded")
    except ManifestTamperedError:
        ctx.record("3. Changed recipient after approval is blocked", True, "ManifestTamperedError")


def scenario_4_expired_grant_blocked(ctx: DemoContext) -> None:
    simulator = PaymentSimulator()
    simulator.fund_account("acct-src", 1_000_000)
    adapter = PaymentSimulatorAdapter(simulator)
    request = PaymentRequest(
        actor=AGENT,
        principal=HUMAN,
        source_account="acct-src",
        beneficiary="merchant-A",
        amount_minor_units=2000,
        currency="INR",
        reference="demo-4",
        idempotency_key="demo-idem-4",
    )
    manifest = ctx.engine.prepare(adapter, request, context=None)
    sealed = ctx.engine.seal(manifest, ctx.signing_key)
    grant = _authorize(
        ctx,
        sealed,
        adapter,
        not_before=ctx.now - timedelta(minutes=10),
        expires_at=ctx.now - timedelta(minutes=1),
    )
    try:
        ctx.engine.commit(sealed, grant, adapter, context=None)
        ctx.record("4. Expired grant", False, "commit unexpectedly succeeded")
    except GrantExpiredError:
        ctx.record("4. Expired grant is blocked", True, "GrantExpiredError")


def scenario_5_revoked_grant_blocked(ctx: DemoContext) -> None:
    simulator = PaymentSimulator()
    simulator.fund_account("acct-src", 1_000_000)
    adapter = PaymentSimulatorAdapter(simulator)
    request = PaymentRequest(
        actor=AGENT,
        principal=HUMAN,
        source_account="acct-src",
        beneficiary="merchant-A",
        amount_minor_units=3000,
        currency="INR",
        reference="demo-5",
        idempotency_key="demo-idem-5",
    )
    manifest = ctx.engine.prepare(adapter, request, context=None)
    sealed = ctx.engine.seal(manifest, ctx.signing_key)
    grant = _authorize(ctx, sealed, adapter)
    ctx.engine.revoke(grant, manifest.manifest_id, revoked_by=HUMAN)
    try:
        ctx.engine.commit(sealed, grant, adapter, context=None)
        ctx.record("5. Revoked grant", False, "commit unexpectedly succeeded")
    except GrantRevokedError:
        ctx.record("5. Revoked grant is blocked", True, "GrantRevokedError")


def scenario_6_and_7_delegation(ctx: DemoContext) -> None:
    from karmasakshi.domain.common import MonetaryAmount
    from karmasakshi.errors import ConstraintWideningError
    from karmasakshi.grants.issuer import issue_grant

    parent = issue_grant(
        grant_id="demo-parent-grant",
        issuer=HUMAN,
        subject=AGENT,
        audience=("payment.simulator",),
        allowed_effect_types=("payment.refund",),
        scope=ScopeConstraints(
            recipients=("merchant-A",),
            max_amount=MonetaryAmount(currency="INR", minor_units=500000),
        ),
        not_before=ctx.now,
        expires_at=ctx.now + timedelta(hours=1),
        nonce="demo-parent-nonce",
        signing_key=ctx.signing_key,
    )

    try:
        ctx.engine.delegate(
            parent,
            issuer=HUMAN,
            subject=AGENT,
            signing_key=ctx.signing_key,
            grant_id="demo-child-wide",
            nonce="demo-child-wide-nonce",
            scope=ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=700000)),
        )
        ctx.record("6. Broader child delegation", False, "delegate() unexpectedly succeeded")
    except ConstraintWideningError:
        ctx.record("6. Broader child delegation is blocked", True, "ConstraintWideningError")

    child = ctx.engine.delegate(
        parent,
        issuer=HUMAN,
        subject=AGENT,
        signing_key=ctx.signing_key,
        grant_id="demo-child-narrow",
        nonce="demo-child-narrow-nonce",
        scope=ScopeConstraints(
            recipients=("merchant-A",),
            max_amount=MonetaryAmount(currency="INR", minor_units=150000),
        ),
    )
    ctx.record(
        "7. Narrow child delegation succeeds",
        child.parent_grant_id == parent.grant_id,
        f"child grant {child.grant_id} narrower-or-equal to parent",
    )


def scenario_8_stale_manifest(ctx: DemoContext) -> None:
    db_path = str(ctx.tmp_dir / "demo_ledger.db")
    adapter = SQLiteRowAdapter(db_path, table="ledger_accounts")
    insert_manifest = adapter.prepare(
        RowEffectRequest(
            operation="insert",
            row_id="demo-acct",
            actor=AGENT,
            principal=HUMAN,
            new_balance=1000,
            idempotency_key="demo-idem-8-insert",
        ),
        context=None,
    )
    adapter.commit(insert_manifest, grant=None, context=None)

    update_manifest = ctx.engine.prepare(
        adapter,
        RowEffectRequest(
            operation="update",
            row_id="demo-acct",
            actor=AGENT,
            principal=HUMAN,
            new_balance=1200,
            idempotency_key="demo-idem-8-update-a",
        ),
        context=None,
    )
    sealed = ctx.engine.seal(update_manifest, ctx.signing_key)
    grant = _authorize(ctx, sealed, adapter)

    # Someone else updates the row after approval but before this commit.
    other_manifest = adapter.prepare(
        RowEffectRequest(
            operation="update",
            row_id="demo-acct",
            actor=AGENT,
            principal=HUMAN,
            new_balance=1300,
            idempotency_key="demo-idem-8-update-b",
        ),
        context=None,
    )
    adapter.commit(other_manifest, grant=None, context=None)

    try:
        ctx.engine.commit(sealed, grant, adapter, context=None)
        ctx.record(
            "8. Stale manifest after external change", False, "commit unexpectedly succeeded"
        )
    except StaleManifestError:
        ctx.record(
            "8. Database change after approval causes STALE_MANIFEST", True, "StaleManifestError"
        )


def scenario_9_concurrent_retries(ctx: DemoContext) -> None:
    simulator = PaymentSimulator()
    simulator.fund_account("acct-src", 1_000_000)
    adapter = PaymentSimulatorAdapter(simulator)
    request = PaymentRequest(
        actor=AGENT,
        principal=HUMAN,
        source_account="acct-src",
        beneficiary="merchant-A",
        amount_minor_units=4000,
        currency="INR",
        reference="demo-9",
        idempotency_key="demo-idem-9",
    )
    manifest = ctx.engine.prepare(adapter, request, context=None)
    sealed = ctx.engine.seal(manifest, ctx.signing_key)
    grant = _authorize(ctx, sealed, adapter)

    successes: list[CommitResult] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def attempt() -> None:
        barrier.wait()
        try:
            result = ctx.engine.commit(sealed, grant, adapter, context=None)
            successes.append(result)
        except KarmaSakshiError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok = len(successes) == 1 and len(errors) == 7
    ctx.record(
        "9. Concurrent payment retries produce one payment",
        ok,
        f"{len(successes)} success, {len(errors)} blocked",
    )


def scenario_10_tampered_signature(ctx: DemoContext) -> None:
    from karmasakshi.errors import InvalidSignatureError

    simulator = PaymentSimulator()
    simulator.fund_account("acct-src", 1_000_000)
    adapter = PaymentSimulatorAdapter(simulator)
    request = PaymentRequest(
        actor=AGENT,
        principal=HUMAN,
        source_account="acct-src",
        beneficiary="merchant-A",
        amount_minor_units=5000,
        currency="INR",
        reference="demo-10",
        idempotency_key="demo-idem-10",
    )
    manifest = ctx.engine.prepare(adapter, request, context=None)
    sealed = ctx.engine.seal(manifest, ctx.signing_key)
    grant = _authorize(ctx, sealed, adapter)

    forged_signature = ctx.other_signing_key.sign(sealed.seal.manifest_hash.encode("utf-8"))
    forged_seal = sealed.seal.model_copy(update={"signature": forged_signature})
    forged_sealed = sealed.model_copy(update={"seal": forged_seal})
    try:
        ctx.engine.commit(forged_sealed, grant, adapter, context=None)
        ctx.record("10. Tampered manifest signature", False, "commit unexpectedly succeeded")
    except InvalidSignatureError:
        ctx.record(
            "10. Tampered manifest fails signature verification", True, "InvalidSignatureError"
        )


def scenario_11_audit_chain_tampering(ctx: DemoContext) -> None:
    from karmasakshi.errors import AuditTamperedError

    events = ctx.engine.context.audit.all_events()
    if len(events) < 2:
        ctx.record("11. Audit-chain tampering", False, "not enough events to tamper with")
        return
    tampered = events[0].model_copy(update={"decision": "tampered-by-demo"})
    events[0] = tampered
    ctx.engine.context.audit._backend._events = events  # type: ignore[attr-defined]
    try:
        ctx.engine.context.audit.verify_chain()
        ctx.record("11. Audit-chain tampering", False, "verify_chain() did not detect tampering")
    except AuditTamperedError:
        ctx.record("11. Audit-chain tampering is detected", True, "AuditTamperedError")


def scenario_12_outcome_mismatch(ctx: DemoContext) -> tuple[Any, Any, Any, Any]:
    class MismatchingAdapter:
        adapter_id = "demo.mismatch"
        adapter_version = "1.0.0"

        def prepare(self, request: Any, context: Any) -> Any:
            return request

        def validate_preconditions(self, manifest: Any, context: Any) -> PreconditionResult:
            return PreconditionResult(satisfied=True)

        def commit(self, manifest: Any, grant: Any, context: Any) -> CommitResult:
            return CommitResult(
                success=True,
                idempotency_key=manifest.idempotency_key,
                provider_reference="ref-mismatch",
            )

        def verify(self, manifest: Any, commit_result: CommitResult, context: Any) -> OutcomeProof:
            return OutcomeProof(
                matched_expected=False,
                observed_at=ctx.clock.now(),
                detail="observed state did not match expected effect",
            )

        def compensate(self, manifest: Any, commit_result: CommitResult, context: Any) -> Any:
            raise NotImplementedError

    from karmasakshi.domain.common import AdapterIdentity
    from karmasakshi.domain.enums import (
        BlastRadiusClassification,
        ReversibilityClassification,
        RiskClassification,
    )
    from karmasakshi.domain.manifest import EffectManifest

    adapter = MismatchingAdapter()
    raw_manifest = EffectManifest(
        manifest_id="demo-mismatch-manifest",
        effect_type="demo.mismatch.effect",
        actor=AGENT,
        principal=HUMAN,
        adapter=AdapterIdentity(
            adapter_id=adapter.adapter_id, adapter_version=adapter.adapter_version
        ),
        target_resource="demo:mismatch/1",
        parameters={"expected": "value-a"},
        risk=RiskClassification.LOW,
        reversibility=ReversibilityClassification.IRREVERSIBLE,
        blast_radius=BlastRadiusClassification.SINGLE_RESOURCE,
        idempotency_key="demo-idem-12",
        created_at=ctx.now,
        expires_at=ctx.now + timedelta(minutes=5),
        nonce="demo-nonce-12",
    )
    manifest = ctx.engine.prepare(adapter, raw_manifest, context=None)
    sealed = ctx.engine.seal(manifest, ctx.signing_key)
    grant = _authorize(ctx, sealed, adapter)
    result = ctx.engine.commit(sealed, grant, adapter, context=None)
    proof = ctx.engine.verify(sealed.manifest, result, adapter, context=None)
    ctx.record(
        "12. External outcome mismatch is detected",
        not proof.matched_expected,
        f"matched_expected={proof.matched_expected}: {proof.detail}",
    )
    return adapter, sealed, result, proof


def scenario_13_supported_compensation(ctx: DemoContext) -> None:
    db_path = str(ctx.tmp_dir / "demo_ledger_2.db")
    adapter = SQLiteRowAdapter(db_path, table="ledger_accounts")
    insert_manifest = adapter.prepare(
        RowEffectRequest(
            operation="insert",
            row_id="demo-acct-2",
            actor=AGENT,
            principal=HUMAN,
            new_balance=1000,
            idempotency_key="demo-idem-13-insert",
        ),
        context=None,
    )
    insert_result = adapter.commit(insert_manifest, grant=None, context=None)
    compensation = adapter.compensate(insert_manifest, insert_result, context=None)
    ctx.record(
        "13. Supported compensation succeeds",
        compensation.succeeded,
        f"attempted={compensation.attempted}, succeeded={compensation.succeeded}",
    )


def scenario_14_irreversible_refuses_compensation(
    ctx: DemoContext, outbox: Any, adapter: Any, sealed: Any, grant: Any
) -> None:
    result = ctx.engine.context.grant_store.get_idempotent_outcome(sealed.manifest.idempotency_key)
    commit_result = CommitResult(
        success=True, idempotency_key=sealed.manifest.idempotency_key, provider_reference=result
    )
    compensation = ctx.engine.compensate(sealed.manifest, commit_result, adapter, context=None)
    ctx.record(
        "14. Irreversible action honestly refuses compensation",
        compensation.attempted is False and compensation.succeeded is False,
        compensation.reason or "",
    )


def scenario_15_export_regression_fixture(
    ctx: DemoContext, mismatch_data: tuple[Any, Any, Any, Any]
) -> None:
    _adapter, sealed, result, proof = mismatch_data
    fixture = export_regression_fixture(
        manifest=sealed.manifest,
        failure_category="verification_mismatch",
        commit_result=result,
        outcome_proof=proof,
        invariant="#20 a successful API response is not proof",
        clock=ctx.clock,
    )
    path = write_fixture(fixture, ctx.tmp_dir / "fixtures" / "mismatch-fixture.json")
    ctx.record(
        "15. Failure exports a regression fixture",
        path.exists(),
        f"written to {path}",
    )


def run_demo() -> bool:
    ctx = _build_context()
    console.print("[bold]KarmaSakshi Protocol -- deterministic demonstration suite[/bold]\n")

    scenario_1_no_valid_grant_is_blocked(ctx)
    outbox, email_adapter, email_sealed, email_grant = scenario_2_exact_approved_email_succeeds(ctx)
    scenario_3_changed_recipient_after_approval_blocked(ctx)
    scenario_4_expired_grant_blocked(ctx)
    scenario_5_revoked_grant_blocked(ctx)
    scenario_6_and_7_delegation(ctx)
    scenario_8_stale_manifest(ctx)
    scenario_9_concurrent_retries(ctx)
    scenario_10_tampered_signature(ctx)
    scenario_11_audit_chain_tampering(ctx)
    mismatch_data = scenario_12_outcome_mismatch(ctx)
    scenario_13_supported_compensation(ctx)
    scenario_14_irreversible_refuses_compensation(
        ctx, outbox, email_adapter, email_sealed, email_grant
    )
    scenario_15_export_regression_fixture(ctx, mismatch_data)

    passed = sum(1 for _, ok, _ in ctx.results if ok)
    total = len(ctx.results)
    console.print(f"\n[bold]{passed}/{total} scenarios behaved as expected.[/bold]")
    return passed == total


def demo(
    ctx: typer.Context,
    all_scenarios: Annotated[bool, typer.Option("--all", help="Run every demo scenario")] = False,
) -> None:
    """Run the deterministic demonstration suite covering every required
    security scenario against the real engine and reference adapters."""
    if not all_scenarios:
        console.print("Pass --all to run the full demonstration suite.")
        raise typer.Exit(code=0)
    ok = run_demo()
    raise typer.Exit(code=0 if ok else 1)


__all__ = ["demo"]
