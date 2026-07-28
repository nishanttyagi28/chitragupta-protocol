"""The ten guided "blocked vs. allowed" scenarios shown on the public demo.

Every scenario below drives the real :class:`ChitraguptaEngine` and real
reference adapters -- nothing here is a mock standing in for the protocol.
The structure deliberately mirrors ``chitragupta.cli.demo_cmd`` (the
deterministic CLI demonstration suite that has been part of this project
since Phase 10); the only difference is that results are captured as
structured :class:`~chitragupta.web.demo_state.ScenarioStep` objects for
HTML rendering instead of being printed to a terminal.
"""

from __future__ import annotations

import threading
import uuid
from datetime import timedelta
from typing import Any

from chitragupta.adapters.base import CommitResult, OutcomeProof, PreconditionResult
from chitragupta.adapters.email_sandbox import EmailRequest, EmailSandboxAdapter, SandboxOutbox
from chitragupta.adapters.payment_simulator import (
    PaymentRequest,
    PaymentSimulator,
    PaymentSimulatorAdapter,
)
from chitragupta.adapters.sqlite_db import RowEffectRequest
from chitragupta.domain.common import AdapterIdentity, MonetaryAmount
from chitragupta.domain.enums import (
    BlastRadiusClassification,
    ReversibilityClassification,
    RiskClassification,
)
from chitragupta.domain.manifest import EffectManifest
from chitragupta.errors import (
    ChitraguptaError,
    ConstraintWideningError,
    GrantExpiredError,
    GrantRevokedError,
    ManifestTamperedError,
    StaleManifestError,
)
from chitragupta.grants.issuer import issue_grant
from chitragupta.grants.model import ScopeConstraints
from chitragupta.web.demo_state import AGENT, APPROVER, DemoSession, ScenarioRun, ScenarioStep

_MAX_STEP_DETAIL = 240


def _short(value: str) -> str:
    return value if len(value) <= _MAX_STEP_DETAIL else value[:_MAX_STEP_DETAIL] + "..."


def _authorize(session: DemoSession, sealed: Any, adapter: Any, **overrides: Any) -> Any:
    now = session.clock.now()
    kwargs: dict[str, Any] = {
        "issuer": APPROVER,
        "subject": AGENT,
        "audience": (adapter.adapter_id,),
        "allowed_effect_types": (sealed.manifest.effect_type,),
        "scope": ScopeConstraints(),
        "not_before": now,
        "expires_at": now + timedelta(minutes=5),
        "signing_key": session.signing_key,
    }
    kwargs.update(overrides)
    return session.engine.authorize(sealed, **kwargs)


def _fresh_payment_adapter(
    session: DemoSession,
) -> tuple[PaymentSimulator, PaymentSimulatorAdapter]:
    simulator = PaymentSimulator()
    simulator.fund_account("demo-treasury", 500_000_00)
    return simulator, PaymentSimulatorAdapter(simulator)


def scenario_no_authorization_blocked(session: DemoSession) -> ScenarioRun:
    steps: list[ScenarioStep] = []
    _simulator, adapter = _fresh_payment_adapter(session)
    request = PaymentRequest(
        actor=AGENT,
        principal=APPROVER,
        source_account="demo-treasury",
        beneficiary="vendor-x",
        amount_minor_units=25_000,
        currency="INR",
        reference="no-auth-demo",
        idempotency_key=f"demo-no-auth-{uuid.uuid4().hex[:8]}",
    )
    manifest = session.engine.prepare(adapter, request, context=None)
    sealed = session.engine.seal(manifest, session.signing_key)
    steps.append(
        ScenarioStep(
            "Prepare + seal effect",
            "info",
            f"Sealed a payment of INR 250.00 to vendor-x (manifest hash "
            f"{sealed.seal.manifest_hash[:20]}...).",
        )
    )
    bogus_grant = issue_grant(
        grant_id=f"bogus-{uuid.uuid4().hex[:8]}",
        issuer=APPROVER,
        subject=AGENT,
        audience=(adapter.adapter_id,),
        allowed_effect_types=(manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=session.clock.now(),
        expires_at=session.clock.now() + timedelta(minutes=5),
        nonce=uuid.uuid4().hex,
        signing_key=session.other_signing_key,
        manifest_hash=sealed.seal.manifest_hash,
    )
    steps.append(
        ScenarioStep(
            "Agent skips AUTHORIZE and attempts to execute directly",
            "info",
            "No human ever approved this effect -- the AUTHORIZE step was never performed. "
            "The engine's lifecycle state machine still requires AUTHORIZED before "
            "COMMITTING, no matter what grant-shaped object is presented.",
        )
    )
    try:
        session.engine.commit(sealed, bogus_grant, adapter, context=None)
        steps.append(ScenarioStep("Result", "error", "Commit unexpectedly succeeded."))
        passed = False
    except ChitraguptaError as exc:
        steps.append(
            ScenarioStep(
                "Result", "blocked", f"Blocked: {type(exc).__name__} -- {_short(str(exc))}"
            )
        )
        passed = True
    return ScenarioRun("no-auth", "Action without authorization is blocked", passed, steps)


def scenario_exact_approved_succeeds(session: DemoSession) -> ScenarioRun:
    steps: list[ScenarioStep] = []
    _simulator, adapter = _fresh_payment_adapter(session)
    request = PaymentRequest(
        actor=AGENT,
        principal=APPROVER,
        source_account="demo-treasury",
        beneficiary="vendor-y",
        amount_minor_units=80_000,
        currency="INR",
        reference="exact-approved-demo",
        idempotency_key=f"demo-exact-{uuid.uuid4().hex[:8]}",
    )
    manifest = session.engine.prepare(adapter, request, context=None)
    sealed = session.engine.seal(manifest, session.signing_key)
    steps.append(
        ScenarioStep("Prepare + seal", "info", "Sealed a payment of INR 800.00 to vendor-y.")
    )
    grant = _authorize(session, sealed, adapter)
    steps.append(
        ScenarioStep(
            "Authorize",
            "ok",
            f"Approver issued Execution Grant {grant.grant_id[:8]}... bound to this exact "
            "sealed effect.",
        )
    )
    result = session.engine.commit(sealed, grant, adapter, context=None)
    proof = session.engine.verify(sealed.manifest, result, adapter, context=None)
    passed = result.success and proof.matched_expected
    steps.append(
        ScenarioStep(
            "Commit + verify",
            "ok" if passed else "error",
            f"Committed (success={result.success}); independently re-verified external state "
            f"(matched_expected={proof.matched_expected}).",
        )
    )
    return ScenarioRun("exact-approved", "Exact approved action succeeds", passed, steps)


def scenario_tampering_blocked(session: DemoSession) -> ScenarioRun:
    steps: list[ScenarioStep] = []
    outbox = SandboxOutbox()
    adapter = EmailSandboxAdapter(outbox)
    idem = f"demo-tamper-{uuid.uuid4().hex[:8]}"
    request = EmailRequest(
        actor=AGENT,
        principal=APPROVER,
        recipients=("customer@example.com",),
        subject="Refund confirmation",
        body="Your refund of INR 800.00 has been approved.",
        idempotency_key=idem,
    )
    manifest = session.engine.prepare(adapter, request, context=None)
    sealed = session.engine.seal(manifest, session.signing_key)
    grant = _authorize(session, sealed, adapter)
    steps.append(
        ScenarioStep(
            "Approve exact effect",
            "info",
            "Approver authorized an email to customer@example.com with this exact subject/body.",
        )
    )
    attacker_request = EmailRequest(
        actor=AGENT,
        principal=APPROVER,
        recipients=("attacker@example.com",),
        subject="Refund confirmation",
        body="Your refund of INR 800.00 has been approved.",
        idempotency_key=idem,
    )
    tampered_manifest = adapter.prepare(attacker_request, context=None)
    tampered_sealed = sealed.model_copy(update={"manifest": tampered_manifest})
    steps.append(
        ScenarioStep(
            "Agent swaps the recipient after approval",
            "info",
            "The recipient is changed to attacker@example.com but the grant presented is the "
            "one issued for the original, approved manifest.",
        )
    )
    try:
        session.engine.commit(tampered_sealed, grant, adapter, context=None)
        steps.append(ScenarioStep("Result", "error", "Commit unexpectedly succeeded."))
        passed = False
    except ManifestTamperedError as exc:
        steps.append(
            ScenarioStep(
                "Result", "blocked", f"Blocked: ManifestTamperedError -- {_short(str(exc))}"
            )
        )
        passed = True
    except ChitraguptaError as exc:
        steps.append(
            ScenarioStep(
                "Result", "blocked", f"Blocked: {type(exc).__name__} -- {_short(str(exc))}"
            )
        )
        passed = True
    return ScenarioRun("tampering", "Amount or recipient tampering is blocked", passed, steps)


def scenario_expired_grant_blocked(session: DemoSession) -> ScenarioRun:
    steps: list[ScenarioStep] = []
    _simulator, adapter = _fresh_payment_adapter(session)
    request = PaymentRequest(
        actor=AGENT,
        principal=APPROVER,
        source_account="demo-treasury",
        beneficiary="vendor-z",
        amount_minor_units=45_000,
        currency="INR",
        reference="expired-demo",
        idempotency_key=f"demo-expired-{uuid.uuid4().hex[:8]}",
    )
    manifest = session.engine.prepare(adapter, request, context=None)
    sealed = session.engine.seal(manifest, session.signing_key)
    now = session.clock.now()
    grant = _authorize(
        session,
        sealed,
        adapter,
        not_before=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=1),
    )
    steps.append(
        ScenarioStep(
            "Authorize with an already-past expiry",
            "info",
            "Grant window: valid 10 minutes ago through 1 minute ago -- already expired at "
            "the moment of use.",
        )
    )
    try:
        session.engine.commit(sealed, grant, adapter, context=None)
        steps.append(ScenarioStep("Result", "error", "Commit unexpectedly succeeded."))
        passed = False
    except GrantExpiredError as exc:
        steps.append(
            ScenarioStep("Result", "blocked", f"Blocked: GrantExpiredError -- {_short(str(exc))}")
        )
        passed = True
    return ScenarioRun("expired", "Expired grant is blocked", passed, steps)


def scenario_revoked_grant_blocked(session: DemoSession) -> ScenarioRun:
    steps: list[ScenarioStep] = []
    _simulator, adapter = _fresh_payment_adapter(session)
    request = PaymentRequest(
        actor=AGENT,
        principal=APPROVER,
        source_account="demo-treasury",
        beneficiary="vendor-w",
        amount_minor_units=60_000,
        currency="INR",
        reference="revoked-demo",
        idempotency_key=f"demo-revoked-{uuid.uuid4().hex[:8]}",
    )
    manifest = session.engine.prepare(adapter, request, context=None)
    sealed = session.engine.seal(manifest, session.signing_key)
    grant = _authorize(session, sealed, adapter)
    steps.append(ScenarioStep("Authorize", "info", f"Grant {grant.grant_id[:8]}... issued."))
    stopped = session.engine.revoke(grant, manifest.manifest_id, revoked_by=APPROVER)
    steps.append(
        ScenarioStep(
            "Approver revokes the grant",
            "info",
            f"Revoked before use (lifecycle stopped at a safe checkpoint: {stopped}).",
        )
    )
    try:
        session.engine.commit(sealed, grant, adapter, context=None)
        steps.append(ScenarioStep("Result", "error", "Commit unexpectedly succeeded."))
        passed = False
    except GrantRevokedError as exc:
        steps.append(
            ScenarioStep("Result", "blocked", f"Blocked: GrantRevokedError -- {_short(str(exc))}")
        )
        passed = True
    return ScenarioRun("revoked", "Revoked grant is blocked", passed, steps)


def scenario_duplicate_retries_execute_once(session: DemoSession) -> ScenarioRun:
    steps: list[ScenarioStep] = []
    _simulator, adapter = _fresh_payment_adapter(session)
    request = PaymentRequest(
        actor=AGENT,
        principal=APPROVER,
        source_account="demo-treasury",
        beneficiary="vendor-v",
        amount_minor_units=15_000,
        currency="INR",
        reference="retry-demo",
        idempotency_key=f"demo-retry-{uuid.uuid4().hex[:8]}",
    )
    manifest = session.engine.prepare(adapter, request, context=None)
    sealed = session.engine.seal(manifest, session.signing_key)
    grant = _authorize(session, sealed, adapter, max_uses=1)
    steps.append(
        ScenarioStep(
            "Simulate a retrying agent",
            "info",
            "6 threads race to commit the same sealed effect with the same single-use grant "
            "(e.g. a client that times out and retries).",
        )
    )
    successes: list[CommitResult] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(6)

    def attempt() -> None:
        barrier.wait()
        try:
            successes.append(session.engine.commit(sealed, grant, adapter, context=None))
        except ChitraguptaError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    passed = len(successes) == 1 and len(errors) == 5
    steps.append(
        ScenarioStep(
            "Result",
            "ok" if passed else "error",
            f"{len(successes)} commit(s) succeeded, {len(errors)} blocked as exhausted/in-flight. "
            "Exactly one real payment was made regardless of how many times the agent retried.",
        )
    )
    return ScenarioRun("duplicate-retry", "Duplicate retries execute only once", passed, steps)


def scenario_stale_state_invalidates_approval(session: DemoSession) -> ScenarioRun:
    steps: list[ScenarioStep] = []
    adapter = session.new_sqlite_adapter(table="demo_toctou")
    insert_manifest = adapter.prepare(
        RowEffectRequest(
            operation="insert",
            row_id="demo-acct",
            actor=AGENT,
            principal=APPROVER,
            new_balance=1000,
            idempotency_key=f"demo-toctou-insert-{uuid.uuid4().hex[:8]}",
        ),
        context=None,
    )
    adapter.commit(insert_manifest, grant=None, context=None)

    update_manifest = session.engine.prepare(
        adapter,
        RowEffectRequest(
            operation="update",
            row_id="demo-acct",
            actor=AGENT,
            principal=APPROVER,
            new_balance=1200,
            idempotency_key=f"demo-toctou-a-{uuid.uuid4().hex[:8]}",
        ),
        context=None,
    )
    sealed = session.engine.seal(update_manifest, session.signing_key)
    grant = _authorize(session, sealed, adapter)
    steps.append(
        ScenarioStep(
            "Approve an update based on the state seen at approval time",
            "info",
            "Approved: set balance to 1200, valid only if the row is still at its "
            "previously-observed version.",
        )
    )

    other_manifest = adapter.prepare(
        RowEffectRequest(
            operation="update",
            row_id="demo-acct",
            actor=AGENT,
            principal=APPROVER,
            new_balance=1300,
            idempotency_key=f"demo-toctou-b-{uuid.uuid4().hex[:8]}",
        ),
        context=None,
    )
    adapter.commit(other_manifest, grant=None, context=None)
    steps.append(
        ScenarioStep(
            "External state changes before execution",
            "info",
            "Something else updates the same row (balance -> 1300) after approval but before "
            "this commit runs.",
        )
    )
    try:
        session.engine.commit(sealed, grant, adapter, context=None)
        steps.append(ScenarioStep("Result", "error", "Commit unexpectedly succeeded."))
        passed = False
    except StaleManifestError as exc:
        steps.append(
            ScenarioStep("Result", "blocked", f"Blocked: StaleManifestError -- {_short(str(exc))}")
        )
        passed = True
    return ScenarioRun("stale-state", "Stale external state invalidates approval", passed, steps)


def scenario_delegation_rejects_broadening(session: DemoSession) -> ScenarioRun:
    steps: list[ScenarioStep] = []
    parent = issue_grant(
        grant_id=f"parent-{uuid.uuid4().hex[:8]}",
        issuer=APPROVER,
        subject=AGENT,
        audience=("payment.simulator",),
        allowed_effect_types=("payment.transfer",),
        scope=ScopeConstraints(
            recipients=("vendor-x",),
            max_amount=MonetaryAmount(currency="INR", minor_units=500_000),
        ),
        not_before=session.clock.now(),
        expires_at=session.clock.now() + timedelta(hours=1),
        nonce=uuid.uuid4().hex,
        signing_key=session.signing_key,
    )
    session.register_grant(f"delegation-root-{parent.grant_id}", parent)
    steps.append(
        ScenarioStep(
            "Root grant issued",
            "info",
            f"Parent grant {parent.grant_id[:8]}... capped at INR 5,000.00, "
            "recipient vendor-x only.",
        )
    )
    try:
        session.engine.delegate(
            parent,
            issuer=APPROVER,
            subject=AGENT,
            signing_key=session.signing_key,
            grant_id=f"child-wide-{uuid.uuid4().hex[:8]}",
            nonce=uuid.uuid4().hex,
            scope=ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=700_000)),
        )
        steps.append(
            ScenarioStep("Broader child delegation", "error", "delegate() unexpectedly succeeded.")
        )
        passed = False
    except ConstraintWideningError as exc:
        steps.append(
            ScenarioStep(
                "Broader child delegation attempted (INR 7,000.00 cap)",
                "blocked",
                f"Blocked: ConstraintWideningError -- {_short(str(exc))}",
            )
        )
        passed = True

    child = session.engine.delegate(
        parent,
        issuer=APPROVER,
        subject=AGENT,
        signing_key=session.signing_key,
        grant_id=f"child-narrow-{uuid.uuid4().hex[:8]}",
        nonce=uuid.uuid4().hex,
        scope=ScopeConstraints(
            recipients=("vendor-x",),
            max_amount=MonetaryAmount(currency="INR", minor_units=150_000),
        ),
    )
    session.register_grant(f"delegation-root-{parent.grant_id}", child)
    steps.append(
        ScenarioStep(
            "Narrower child delegation (INR 1,500.00 cap) succeeds",
            "ok",
            f"Child grant {child.grant_id[:8]}... issued, narrower-or-equal to its parent on "
            "every dimension.",
        )
    )
    return ScenarioRun("delegation", "Broader child delegation is rejected", passed, steps)


def scenario_audit_tampering_detected(session: DemoSession) -> ScenarioRun:
    from chitragupta.errors import AuditTamperedError

    steps: list[ScenarioStep] = []
    events = session.engine.context.audit.all_events()
    if len(events) < 2:
        # Guarantee at least two events exist regardless of what has run before.
        outbox = SandboxOutbox()
        filler_adapter = EmailSandboxAdapter(outbox)
        filler = session.engine.prepare(
            filler_adapter,
            EmailRequest(
                actor=AGENT,
                principal=APPROVER,
                recipients=("filler@example.com",),
                subject="filler",
                body="filler",
                idempotency_key=f"demo-audit-filler-{uuid.uuid4().hex[:8]}",
            ),
            context=None,
        )
        session.engine.seal(filler, session.signing_key)
        events = session.engine.context.audit.all_events()

    steps.append(
        ScenarioStep(
            "Audit journal state",
            "info",
            f"{len(events)} hash-chained events recorded so far.",
        )
    )
    tampered = events[0].model_copy(update={"decision": "tampered-by-demo"})
    events[0] = tampered
    session.engine.context.audit._backend._events = events  # type: ignore[attr-defined]
    steps.append(
        ScenarioStep(
            "An attacker edits one historical event in place",
            "info",
            "The event's stored fields are changed directly in the backend, bypassing the "
            "append-only API.",
        )
    )
    try:
        session.engine.context.audit.verify_chain()
        steps.append(ScenarioStep("Result", "error", "verify_chain() did not detect tampering."))
        passed = False
    except AuditTamperedError as exc:
        steps.append(
            ScenarioStep("Result", "blocked", f"Detected: AuditTamperedError -- {_short(str(exc))}")
        )
        passed = True
    return ScenarioRun("audit-tamper", "Audit-chain tampering is detected", passed, steps)


def scenario_outcome_mismatch_detected(session: DemoSession) -> ScenarioRun:
    steps: list[ScenarioStep] = []

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
                observed_at=session.clock.now(),
                detail="observed external state did not match the approved effect",
            )

        def compensate(self, manifest: Any, commit_result: CommitResult, context: Any) -> Any:
            raise NotImplementedError

    adapter = MismatchingAdapter()
    idem = f"demo-mismatch-{uuid.uuid4().hex[:8]}"
    raw_manifest = EffectManifest(
        manifest_id=str(uuid.uuid4()),
        effect_type="demo.mismatch.effect",
        actor=AGENT,
        principal=APPROVER,
        adapter=AdapterIdentity(
            adapter_id=adapter.adapter_id, adapter_version=adapter.adapter_version
        ),
        target_resource="demo:mismatch/1",
        parameters={"expected": "value-a"},
        risk=RiskClassification.LOW,
        reversibility=ReversibilityClassification.IRREVERSIBLE,
        blast_radius=BlastRadiusClassification.SINGLE_RESOURCE,
        idempotency_key=idem,
        created_at=session.clock.now(),
        expires_at=session.clock.now() + timedelta(minutes=5),
        nonce=uuid.uuid4().hex,
    )
    manifest = session.engine.prepare(adapter, raw_manifest, context=None)
    sealed = session.engine.seal(manifest, session.signing_key)
    grant = _authorize(session, sealed, adapter)
    steps.append(ScenarioStep("Approve + commit", "info", "Adapter reports the commit succeeded."))
    result = session.engine.commit(sealed, grant, adapter, context=None)
    proof = session.engine.verify(sealed.manifest, result, adapter, context=None)
    passed = not proof.matched_expected
    steps.append(
        ScenarioStep(
            "Independent verification re-observes external state",
            "blocked" if passed else "error",
            f"matched_expected={proof.matched_expected}: {_short(proof.detail or '')} -- a "
            "successful commit response alone is never treated as proof of the real outcome.",
        )
    )
    return ScenarioRun("outcome-mismatch", "Outcome mismatch is detected", passed, steps)


SCENARIOS: dict[str, Any] = {
    "no-auth": scenario_no_authorization_blocked,
    "exact-approved": scenario_exact_approved_succeeds,
    "tampering": scenario_tampering_blocked,
    "expired": scenario_expired_grant_blocked,
    "revoked": scenario_revoked_grant_blocked,
    "duplicate-retry": scenario_duplicate_retries_execute_once,
    "stale-state": scenario_stale_state_invalidates_approval,
    "delegation": scenario_delegation_rejects_broadening,
    "audit-tamper": scenario_audit_tampering_detected,
    "outcome-mismatch": scenario_outcome_mismatch_detected,
}

SCENARIO_ORDER = [
    "no-auth",
    "exact-approved",
    "tampering",
    "expired",
    "revoked",
    "duplicate-retry",
    "stale-state",
    "delegation",
    "audit-tamper",
    "outcome-mismatch",
]

SCENARIO_TITLES = {
    "no-auth": "Action without authorization is blocked",
    "exact-approved": "Exact approved action succeeds",
    "tampering": "Amount or recipient tampering is blocked",
    "expired": "Expired grant is blocked",
    "revoked": "Revoked grant is blocked",
    "duplicate-retry": "Duplicate retries execute only once",
    "stale-state": "Stale external state invalidates approval",
    "delegation": "Broader child delegation is rejected",
    "audit-tamper": "Audit-chain tampering is detected",
    "outcome-mismatch": "Outcome mismatch is detected",
}

__all__ = ["SCENARIOS", "SCENARIO_ORDER", "SCENARIO_TITLES"]
