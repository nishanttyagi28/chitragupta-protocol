"""The AI-operated customer refund journey (Milestone A's named first
commercial use case): propose -> assess -> approve -> commit -> verify
-> passport, plus honest ambiguous-outcome recovery and compensation,
all scoped to one organization's isolated engine/adapter/audit state.

Deliberately narrow. This is not a general-purpose multi-effect-type API
-- see `karmasakshi.api.routes` for that -- it wires the existing,
already-tested engine/adapter/compensation library functions to the
refund vertical specifically, the same way the CLI's ``demo`` command
wires them for a terminal walkthrough. See docs/gateway.md.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.adapters.payment_simulator import PaymentRequest, PaymentSimulatorAdapter
from karmasakshi.approval import (
    ApprovalPolicy,
    build_approval_policy_bundle,
    sign_approval_statement,
)
from karmasakshi.compensation import build_compensation_manifest
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import KarmaSakshiError
from karmasakshi.gateway.api import (
    require_gateway_session,
    require_registered_refund_resources,
    resolve_org_runtime,
)
from karmasakshi.gateway.models import GatewayUser, GatewayUserRole
from karmasakshi.gateway.refund_schemas import (
    RefundAssessmentOut,
    RefundDenyIn,
    RefundDenyResult,
    RefundDetailOut,
    RefundEffectView,
    RefundListOut,
    RefundPolicyDecisionOut,
    RefundSummaryOut,
)
from karmasakshi.gateway.schemas import validate_principal_safe_id
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.intelligence.policy import (
    POLICY_TYPE_INTELLIGENCE,
    IntelligencePolicy,
    build_policy_bundle,
    policy_from_bundle_payload,
)
from karmasakshi.passports import (
    build_passport,
    build_passport_v2,
    render_passport_html,
    render_passport_markdown,
    render_passport_v2_html,
    render_passport_v2_markdown,
)
from karmasakshi.policy import seal_policy_bundle, verify_policy_bundle
from karmasakshi.portable import build_evidence_pack

router = APIRouter(prefix="/gateway/organizations/{org_id}", tags=["gateway-refunds"])

_PAYMENT_ADAPTER_ID = "payment.simulator"
_PAYMENT_ADAPTER_VERSION = "1.0.0"


class PolicyActivateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    block_threshold: int = 80
    review_threshold: int = 50
    effective_seconds: int = 365 * 24 * 3600


class RefundProposeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    requested_by: str
    source_account: str = "acct-src"
    beneficiary: str
    amount_minor_units: int
    currency: str = "INR"
    reference: str
    idempotency_key: str

    @field_validator("agent_id", "requested_by")
    @classmethod
    def _validate_principal_ids(cls, v: str) -> str:
        return validate_principal_safe_id(v)


class RefundApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttl_seconds: int = 300
    policy_bundle_id: str | None = None


class RefundCompensateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttl_seconds: int = 300


class RefundExecuteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str


def _agent(principal_id: str) -> Principal:
    return Principal(principal_id=principal_id, principal_type=PrincipalType.AGENT)


def _human(principal_id: str) -> Principal:
    return Principal(principal_id=principal_id, principal_type=PrincipalType.HUMAN)


def _active_intelligence_policy(state: Any) -> IntelligencePolicy | None:
    """Resolve and verify this organization's currently activated
    `IntelligencePolicy`, or ``None`` if no policy has been activated
    (RA-003).

    Fails closed with an ``HTTPException`` rather than silently falling
    back to the engine's default policy if an activated bundle exists but
    no longer verifies (tampered, expired, or wrong type) -- silently
    assessing under a different, possibly more lenient policy than the one
    the organization believes is active would defeat the point of this
    fix.
    """
    bundle_id = state.active_policy_bundle_id
    if bundle_id is None:
        return None
    sealed_bundle = state.policy_bundles.get(bundle_id)
    if sealed_bundle is None:
        raise HTTPException(500, "active policy bundle is unavailable")
    try:
        verify_policy_bundle(
            sealed_bundle,
            state.keyring,
            now=state.engine.context.clock.now(),
            expected_policy_type=POLICY_TYPE_INTELLIGENCE,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(409, f"active policy bundle failed verification: {exc}") from exc
    return policy_from_bundle_payload(sealed_bundle.bundle.payload)


def _assessment_out(assessment: Any) -> RefundAssessmentOut:
    return RefundAssessmentOut(
        score=assessment.score,
        risk_level=assessment.risk_level.value,
        signals=assessment.signals,
        recommendation=assessment.recommendation.value,
        required_human_approvals=assessment.required_human_approvals,
        required_service_approvals=assessment.required_service_approvals,
        cooling_off_period_seconds=assessment.cooling_off_period_seconds,
        required_witness_quorum=assessment.required_witness_quorum,
        required_verification_strength=assessment.required_verification_strength.value,
        policy_id=assessment.policy_id,
        policy_version=assessment.policy_version,
        policy_hash=assessment.policy_hash,
        explanation=assessment.explanation,
    )


def _denial_event(state: Any, manifest_id: str) -> Any | None:
    events = state.engine.context.audit.events_for_manifest(manifest_id)
    return next(
        (
            event
            for event in reversed(events)
            if event.event_type == "manifest.authorization_denied"
        ),
        None,
    )


def _verification_status(
    *, commit_attempted: bool, commit_success: bool | None, ambiguous: bool, proof: Any | None
) -> str:
    if proof is not None:
        return "verified_match" if proof.matched_expected else "verified_mismatch"
    if ambiguous:
        return "ambiguous"
    if not commit_attempted:
        return "not_started"
    if commit_success is True:
        return "pending"
    return "failed"


def _refund_detail(state: Any, org_id: str, manifest_id: str) -> RefundDetailOut:
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "refund not found")
    manifest = sealed.manifest
    if manifest.effect_type != "payment.transfer" or manifest.parent_manifest_id is not None:
        raise HTTPException(404, "refund not found")
    assessment = state.assessments.get(manifest_id)
    if assessment is None:
        raise HTTPException(500, "refund assessment unavailable")

    timeline = state.engine.context.audit.events_for_manifest(manifest_id)
    denied = _denial_event(state, manifest_id)
    grant_ids = state.grants_by_manifest.get(manifest_id, [])
    grant = state.grants.get(grant_ids[-1]) if grant_ids else None
    approval_statements = state.approval_statements.get(manifest_id, [])
    lifecycle_state = state.engine.get_lifecycle_state(manifest_id).value
    decision_status = "denied" if denied is not None else ("approved" if grant else "pending")
    commit = state.commit_results.get(manifest_id)
    proof = state.outcome_proofs.get(manifest_id)
    ambiguous = bool(
        proof is None and commit and commit.detail and "ambiguous" in commit.detail.casefold()
    )

    fingerprint = manifest.state_fingerprint
    if fingerprint is None or not fingerprint.value.startswith("balance:"):
        raise HTTPException(500, "refund before-state fingerprint unavailable")
    try:
        source_balance_before = int(fingerprint.value.removeprefix("balance:"))
        amount = int(manifest.parameters["amount_minor_units"])
        fee = int(manifest.parameters["fee_minor_units"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(500, "refund effect parameters unavailable") from exc

    observed_digest = None
    if proof is not None:
        observed_digest = proof.observed_after_state_digest
    elif commit is not None:
        observed_digest = commit.after_state_digest

    effect = RefundEffectView(
        source_account=str(manifest.parameters["source_account"]),
        beneficiary=str(manifest.parameters["beneficiary"]),
        amount_minor_units=amount,
        fee_minor_units=fee,
        currency=str(manifest.parameters["currency"]),
        reference=str(manifest.parameters["reference"]),
        idempotency_key=manifest.idempotency_key,
        source_balance_before_minor_units=source_balance_before,
        source_balance_expected_after_minor_units=source_balance_before - amount - fee,
        beneficiary_credit_expected_after_minor_units=amount,
        observed_after_state_digest=observed_digest,
    )
    assessment_out = _assessment_out(assessment)
    return RefundDetailOut(
        org_id=org_id,
        manifest_id=manifest_id,
        manifest_hash=sealed.seal.manifest_hash,
        actor_id=manifest.actor.principal_id,
        requested_by=manifest.principal.principal_id,
        created_at=manifest.created_at,
        expires_at=manifest.expires_at,
        lifecycle_state=lifecycle_state,
        decision_status=decision_status,
        denied_by=None if denied is None else denied.actor_id,
        denial_reason=None if denied is None else denied.metadata.get("reason"),
        can_approve=lifecycle_state == "sealed" and denied is None and grant is None,
        can_deny=lifecycle_state == "sealed" and denied is None and grant is None,
        grant_id=None if grant is None else grant.grant_id,
        authorized_by=None if grant is None else grant.issuer.principal_id,
        effect=effect,
        assessment=assessment_out,
        policy_decision=RefundPolicyDecisionOut(
            recommendation=assessment.recommendation.value,
            policy_id=assessment.policy_id,
            policy_version=assessment.policy_version,
            policy_hash=assessment.policy_hash,
            active_policy_bundle_id=state.active_policy_bundle_id,
            bound_policy_bundle_hash=None if grant is None else grant.policy_bundle_hash,
            required_human_approvals=assessment.required_human_approvals,
            completed_human_approvals=len(approval_statements),
            required_service_approvals=assessment.required_service_approvals,
            cooling_off_period_seconds=assessment.cooling_off_period_seconds,
            required_witness_quorum=assessment.required_witness_quorum,
            required_verification_strength=assessment.required_verification_strength.value,
        ),
        commit_attempted=commit is not None,
        commit_success=None if commit is None else commit.success,
        provider_reference=None if commit is None else commit.provider_reference,
        commit_detail=None if commit is None else commit.detail,
        ambiguous=ambiguous,
        verification_status=_verification_status(
            commit_attempted=commit is not None,
            commit_success=None if commit is None else commit.success,
            ambiguous=ambiguous,
            proof=proof,
        ),
        verification_matched_expected=None if proof is None else proof.matched_expected,
        verification_detail=None if proof is None else proof.detail,
        timeline=timeline,
    )


def _refund_summary(detail: RefundDetailOut) -> RefundSummaryOut:
    return RefundSummaryOut(
        manifest_id=detail.manifest_id,
        manifest_hash=detail.manifest_hash,
        created_at=detail.created_at,
        beneficiary=detail.effect.beneficiary,
        amount_minor_units=detail.effect.amount_minor_units,
        currency=detail.effect.currency,
        reference=detail.effect.reference,
        lifecycle_state=detail.lifecycle_state,
        decision_status=detail.decision_status,
        risk_score=detail.assessment.score,
        risk_level=detail.assessment.risk_level,
        recommendation=detail.assessment.recommendation,
        ambiguous=detail.ambiguous,
        verification_status=detail.verification_status,
    )


@router.post("/evaluation/payment-simulator/ambiguous-next")
def inject_payment_simulator_ambiguity(
    org_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, bool]:
    """Arm the real payment simulator's documented ambiguous-timeout mode.

    This is deliberately evaluation-only and simulator-specific: the next
    commit settles in the simulator's ledger but returns a timeout, allowing
    buyers to exercise observation-based recovery without fabricated UI state.
    """
    state = resolve_org_runtime(request, user, org_id)
    adapter = state.adapters.get(_PAYMENT_ADAPTER_ID)
    if not isinstance(adapter, PaymentSimulatorAdapter):
        raise HTTPException(409, "payment simulator is not available")
    adapter.simulator.inject_ambiguous_timeout()
    state.engine.context.audit.record(
        event_type="evaluation.payment_simulator.ambiguous_timeout_armed",
        decision="armed",
        actor_id=user.user_id,
        metadata={"adapter_id": _PAYMENT_ADAPTER_ID},
    )
    return {"armed": True}


@router.post("/policy")
def activate_policy(
    org_id: str,
    body: PolicyActivateIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """Build, sign, and activate a risk-scoring policy for this
    organization. The active bundle is bound into every subsequent
    refund's grant at approval time (invariant #31: a grant bound to a
    policy bundle cannot commit against a missing, different, tampered,
    expired, or unsigned-by-an-untrusted-key policy bundle). The issuer
    is the authenticated session user, never a client-supplied identity
    claim."""
    state = resolve_org_runtime(request, user, org_id)
    # RA-005: the active policy now actually governs assessment (RA-003),
    # so any member being able to activate a lenient policy would let them
    # weaken risk scoring for their own proposals. Restrict activation to
    # owners, same as user creation.
    if user.role != GatewayUserRole.OWNER:
        raise HTTPException(403, "only an organization owner may activate a policy")
    now = datetime.now(timezone.utc)
    policy = IntelligencePolicy(
        policy_id=body.bundle_id,
        block_threshold=body.block_threshold,
        review_threshold=body.review_threshold,
    )
    try:
        bundle = build_policy_bundle(
            policy,
            bundle_id=body.bundle_id,
            bundle_version="1.0",
            issuer=_human(user.user_id),
            created_at=now,
            effective_from=now,
            effective_until=now + timedelta(seconds=body.effective_seconds),
            tenant_id=org_id,
        )
        sealed = seal_policy_bundle(bundle, state.signing_key)
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.policy_bundles[body.bundle_id] = sealed
    state.active_policy_bundle_id = body.bundle_id
    return {
        "bundle_id": body.bundle_id,
        "bundle_hash": sealed.seal.bundle_hash,
        "active": True,
    }


@router.get("/refunds")
def list_refunds(
    org_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
    decision_status: str | None = Query(default=None, max_length=32),
) -> RefundListOut:
    """List the authenticated organization's refund effects.

    The organization scope is resolved before any manifest is enumerated,
    so an otherwise-valid session cannot use this read model to discover
    another tenant's identifiers or aggregate counts.
    """
    state = resolve_org_runtime(request, user, org_id)
    refund_ids = [
        mid
        for mid, sealed in state.sealed_manifests.items()
        if sealed.manifest.effect_type == "payment.transfer"
        and sealed.manifest.parent_manifest_id is None
    ]
    details = [_refund_detail(state, org_id, mid) for mid in refund_ids]
    refunds = [_refund_summary(detail) for detail in details]
    if decision_status is not None:
        normalized = decision_status.strip().casefold()
        if normalized not in {"pending", "approved", "denied"}:
            raise HTTPException(400, "decision_status must be pending, approved, or denied")
        refunds = [refund for refund in refunds if refund.decision_status == normalized]
    refunds.sort(key=lambda refund: refund.created_at, reverse=True)
    return RefundListOut(refunds=refunds)


@router.get("/refunds/{manifest_id}")
def get_refund(
    org_id: str,
    manifest_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> RefundDetailOut:
    state = resolve_org_runtime(request, user, org_id)
    return _refund_detail(state, org_id, manifest_id)


@router.post("/refunds/propose")
def propose_refund(
    org_id: str,
    body: RefundProposeIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """Propose an exact refund effect: prepare + seal + run the
    (advisory) Effect Intelligence Engine risk assessment."""
    state = require_registered_refund_resources(
        request,
        user,
        org_id,
        agent_id=body.agent_id,
        adapter_id=_PAYMENT_ADAPTER_ID,
        adapter_version=_PAYMENT_ADAPTER_VERSION,
    )
    adapter = state.adapters[_PAYMENT_ADAPTER_ID]
    payment_request = PaymentRequest(
        actor=_agent(body.agent_id),
        principal=_human(body.requested_by),
        source_account=body.source_account,
        beneficiary=body.beneficiary,
        amount_minor_units=body.amount_minor_units,
        currency=body.currency,
        reference=body.reference,
        idempotency_key=body.idempotency_key,
    )
    active_policy = _active_intelligence_policy(state)
    try:
        manifest = state.engine.prepare(adapter, payment_request, context=None)
        sealed = state.engine.seal(manifest, state.signing_key)
        assessment = state.engine.assess(manifest, policy=active_policy)
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.sealed_manifests[manifest.manifest_id] = sealed
    state.assessments[manifest.manifest_id] = assessment
    now = state.engine.context.clock.now()
    approval_policy = build_approval_policy_bundle(
        ApprovalPolicy(
            policy_id=f"refund-quorum-{manifest.manifest_id}",
            required_approvals=max(1, assessment.required_human_approvals),
        ),
        bundle_id=f"refund-quorum-{manifest.manifest_id}",
        bundle_version="1.0",
        issuer=Principal(
            principal_id="gateway-quorum-service",
            principal_type=PrincipalType.SERVICE,
        ),
        tenant_id=org_id,
        created_at=now,
        effective_from=now,
    )
    state.approval_policy_bundles[manifest.manifest_id] = seal_policy_bundle(
        approval_policy,
        state.signing_key,
        clock=state.engine.context.clock,
    )
    return {
        "manifest_id": manifest.manifest_id,
        "manifest_hash": sealed.seal.manifest_hash,
        "assessment": _assessment_out(assessment).model_dump(mode="json"),
    }


@router.post("/refunds/{manifest_id}/approve")
def approve_refund(
    org_id: str,
    manifest_id: str,
    body: RefundApproveIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """Record one distinct human approval and issue a quorum-bound grant.

    The approver identity comes exclusively from the authenticated
    Gateway session. No grant is issued until the assessment's required
    human approval count is satisfied by distinct organization users.
    """
    state = resolve_org_runtime(request, user, org_id)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    if _denial_event(state, manifest_id) is not None:
        raise HTTPException(409, "refund authorization was denied")
    if state.grants_by_manifest.get(manifest_id):
        raise HTTPException(409, "refund is already authorized")
    assessment = state.assessments.get(manifest_id)
    approval_policy_bundle = state.approval_policy_bundles.get(manifest_id)
    if assessment is None or approval_policy_bundle is None:
        raise HTTPException(500, "refund approval policy unavailable")
    statements = state.approval_statements.setdefault(manifest_id, [])
    if any(statement.approver.principal_id == user.user_id for statement in statements):
        raise HTTPException(409, "this user already approved the refund")
    policy_bundle = None
    bundle_id = body.policy_bundle_id or state.active_policy_bundle_id
    if bundle_id is not None:
        policy_bundle = state.policy_bundles.get(bundle_id)
        if policy_bundle is None:
            raise HTTPException(404, f"policy bundle {bundle_id!r} not found")
    now = datetime.now(timezone.utc)
    try:
        statement = sign_approval_statement(
            statement_id=str(uuid.uuid4()),
            manifest_hash=sealed.seal.manifest_hash,
            approval_policy_bundle_hash=approval_policy_bundle.seal.bundle_hash,
            approver=_human(user.user_id),
            decision="approve",
            signing_key=state.signing_key,
            expires_at=now + timedelta(seconds=body.ttl_seconds),
            nonce=uuid.uuid4().hex,
            clock=state.engine.context.clock,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(403, str(exc)) from exc
    statements.append(statement)
    required = max(1, assessment.required_human_approvals)
    state.engine.context.audit.record(
        event_type="approval.statement_recorded",
        decision="approve",
        manifest_id=manifest_id,
        manifest_hash=sealed.seal.manifest_hash,
        actor_id=user.user_id,
        metadata={
            "statement_id": statement.statement_id,
            "completed_human_approvals": str(len(statements)),
            "required_human_approvals": str(required),
        },
    )
    if len(statements) < required:
        return {
            "grant_id": None,
            "policy_bundle_hash": None,
            "completed_human_approvals": len(statements),
            "required_human_approvals": required,
            "authorized": False,
        }
    try:
        grant = state.engine.authorize_with_quorum(
            sealed,
            statements=tuple(statements),
            approval_policy_bundle=approval_policy_bundle,
            proposer=sealed.manifest.actor,
            subject=sealed.manifest.actor,
            grant_issuer=Principal(
                principal_id="gateway-quorum-service",
                principal_type=PrincipalType.SERVICE,
            ),
            audience=(_PAYMENT_ADAPTER_ID,),
            allowed_effect_types=(sealed.manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(seconds=body.ttl_seconds),
            signing_key=state.signing_key,
            policy_bundle=policy_bundle,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(403, str(exc)) from exc
    state.register_grant(manifest_id, grant)
    return {
        "grant_id": grant.grant_id,
        "policy_bundle_hash": grant.policy_bundle_hash,
        "completed_human_approvals": len(statements),
        "required_human_approvals": required,
        "authorized": True,
    }


@router.post("/refunds/{manifest_id}/deny")
def deny_refund(
    org_id: str,
    manifest_id: str,
    body: RefundDenyIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> RefundDenyResult:
    """Record a fail-closed human denial for one exact sealed effect.

    The denying identity is taken exclusively from the authenticated
    Gateway session. A denied effect remains sealed but can never be
    approved by this refund API; the denial itself is durable in the
    organization's append-only audit journal.
    """
    state = resolve_org_runtime(request, user, org_id)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    if _denial_event(state, manifest_id) is not None:
        raise HTTPException(409, "refund authorization was already denied")
    lifecycle_state = state.engine.get_lifecycle_state(manifest_id).value
    if lifecycle_state != "sealed" or state.grants_by_manifest.get(manifest_id):
        raise HTTPException(409, "only a pending sealed refund can be denied")
    state.engine.context.audit.record(
        event_type="manifest.authorization_denied",
        decision="denied",
        manifest_id=manifest_id,
        manifest_hash=sealed.seal.manifest_hash,
        actor_id=user.user_id,
        from_state=lifecycle_state,
        to_state=lifecycle_state,
        metadata={"reason": body.reason},
    )
    return RefundDenyResult(
        manifest_id=manifest_id,
        denied=True,
        denied_by=user.user_id,
        reason=body.reason,
    )


@router.post("/refunds/{manifest_id}/execute")
def execute_refund(
    org_id: str,
    manifest_id: str,
    body: RefundExecuteIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """Commit exactly once through the payment simulator. A manifest
    whose amount/recipient was modified after sealing, or an already-used
    grant (duplicate retry), fails closed here -- invariants #1-#5, #11."""
    state = resolve_org_runtime(request, user, org_id)
    sealed = state.sealed_manifests.get(manifest_id)
    grant = state.grants.get(body.grant_id)
    if sealed is None or grant is None:
        raise HTTPException(404, "manifest or grant not found")
    policy_bundle = None
    if grant.policy_bundle_hash is not None:
        policy_bundle = state.policy_bundles.get(state.active_policy_bundle_id or "")
        if policy_bundle is None or policy_bundle.seal.bundle_hash != grant.policy_bundle_hash:
            raise HTTPException(409, "grant is policy-bound but the matching bundle is unavailable")
    adapter = state.adapters[_PAYMENT_ADAPTER_ID]
    try:
        result = state.engine.commit(
            sealed, grant, adapter, context=None, policy_bundle=policy_bundle
        )
    except KarmaSakshiError as exc:
        raise HTTPException(409, str(exc)) from exc
    state.commit_results[manifest_id] = result
    return {
        "success": result.success,
        "provider_reference": result.provider_reference,
        "detail": result.detail,
    }


@router.post("/refunds/{manifest_id}/verify")
def verify_refund(
    org_id: str,
    manifest_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """Independent post-commit observation via the simulator's own
    system of record -- a successful commit response is never treated as
    proof (invariants #20/#21)."""
    state = resolve_org_runtime(request, user, org_id)
    sealed = state.sealed_manifests.get(manifest_id)
    result = state.commit_results.get(manifest_id)
    if sealed is None or result is None:
        raise HTTPException(404, "manifest or commit result not found")
    adapter = state.adapters[_PAYMENT_ADAPTER_ID]
    proof = state.engine.verify(sealed.manifest, result, adapter, context=None)
    state.outcome_proofs[manifest_id] = proof
    return {"matched_expected": proof.matched_expected, "detail": proof.detail}


@router.post("/refunds/{manifest_id}/recover")
def recover_refund(
    org_id: str,
    manifest_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """Recover from an ambiguous commit outcome (e.g. a provider timeout)
    by re-observing external state first -- never a blind retry. Honestly
    reports whatever the re-observation actually shows, including
    'still ambiguous' if the provider offers no evidence either way."""
    state = resolve_org_runtime(request, user, org_id)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    adapter = state.adapters[_PAYMENT_ADAPTER_ID]
    try:
        proof = state.engine.recover_ambiguous_commit(sealed.manifest, adapter, context=None)
    except KarmaSakshiError as exc:
        raise HTTPException(409, str(exc)) from exc
    state.outcome_proofs[manifest_id] = proof
    return {"matched_expected": proof.matched_expected, "detail": proof.detail}


@router.post("/refunds/{manifest_id}/compensate")
def compensate_refund(
    org_id: str,
    manifest_id: str,
    body: RefundCompensateIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """Compensation as a separate, separately-authorized effect: builds a
    compensation manifest cryptographically bound to the original
    (invariant #43), authorizes and commits it in one call for buyer
    evaluation simplicity. The caller must have been one of the original
    refund's distinct quorum approvers (RA-008) -- this narrows who may
    single-handedly authorize a reversal, but it is not yet a full
    separate compensation quorum/review step of its own; see
    docs/limitations.md. Reports the honest triad -- attempted vs.
    succeeded are independent booleans; a settled payment's compensation
    is truthfully refused (`succeeded=False`), never silently upgraded.
    The approver is the authenticated session user."""
    state = resolve_org_runtime(request, user, org_id)
    original = state.sealed_manifests.get(manifest_id)
    original_commit = state.commit_results.get(manifest_id)
    if original is None or original_commit is None:
        raise HTTPException(404, "manifest or commit result not found")
    # RA-008: compensation is a distinct authorized effect, but nothing
    # required the caller to have had any part in authorizing the
    # *original* refund -- any authenticated org member could single-
    # handedly reverse a refund they had no prior authority over. Require
    # the caller to have been one of the original refund's distinct
    # quorum approvers (a real, not fabricated, prior involvement).
    original_approvers = {
        statement.approver.principal_id
        for statement in state.approval_statements.get(manifest_id, [])
    }
    if user.user_id not in original_approvers:
        raise HTTPException(
            403, "only a user who approved the original refund may authorize its compensation"
        )
    now = datetime.now(timezone.utc)
    adapter = state.adapters[_PAYMENT_ADAPTER_ID]
    try:
        unsigned = build_compensation_manifest(original=original, original_commit=original_commit)
        state.engine.prepare_compensation(unsigned, original_sealed=original)
        compensation_sealed = state.engine.seal(unsigned, state.signing_key)
        grant = state.engine.authorize_compensation(
            original,
            compensation_sealed,
            issuer=_human(user.user_id),
            subject=original.manifest.actor,
            audience=(_PAYMENT_ADAPTER_ID,),
            allowed_effect_types=(compensation_sealed.manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(seconds=body.ttl_seconds),
            signing_key=state.signing_key,
        )
        result = state.engine.commit_compensation(
            original,
            compensation_sealed,
            grant,
            adapter,
            context=None,
            original_commit=original_commit,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(409, str(exc)) from exc
    state.sealed_manifests[compensation_sealed.manifest.manifest_id] = compensation_sealed
    state.register_grant(compensation_sealed.manifest.manifest_id, grant)
    state.commit_results[compensation_sealed.manifest.manifest_id] = result
    return {
        "compensation_manifest_id": compensation_sealed.manifest.manifest_id,
        "attempted": result.success or result.detail is not None,
        "succeeded": result.success,
        "detail": result.detail,
    }


@router.get("/refunds/{manifest_id}/passport")
def refund_passport(
    org_id: str,
    manifest_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
    fmt: str = "json",
    version: str = "v1",
) -> Any:
    """Action Passport: independently re-verifies the seal, grant, and
    audit chain at generation time, then proves the proposed -> approved
    -> committed -> verified chain for this one exact effect. See
    docs/action-passports.md / docs/action-passport-v2.md."""
    state = resolve_org_runtime(request, user, org_id)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    grant_ids = state.grants_by_manifest.get(manifest_id, [])
    grant = state.grants[grant_ids[-1]] if grant_ids else None
    lifecycle_state = state.engine.get_lifecycle_state(manifest_id).value
    commit_result = state.commit_results.get(manifest_id)
    outcome_proof = state.outcome_proofs.get(manifest_id)
    assessment = state.assessments.get(manifest_id)
    ver = version.strip().lower()
    if ver in {"v2", "2", "2.0"}:
        passport_v2 = build_passport_v2(
            sealed=sealed,
            keyring=state.keyring,
            audit=state.engine.context.audit,
            lifecycle_state=lifecycle_state,
            grant=grant,
            grant_store=state.engine.context.grant_store,
            commit_result=commit_result,
            outcome_proof=outcome_proof,
            assessment=assessment,
            tenant_id=org_id,
        )
        if fmt == "html":
            from fastapi.responses import HTMLResponse

            return HTMLResponse(render_passport_v2_html(passport_v2))
        if fmt == "markdown":
            from fastapi.responses import PlainTextResponse

            return PlainTextResponse(render_passport_v2_markdown(passport_v2))
        return passport_v2.model_dump(mode="json")
    if ver not in {"v1", "1", "1.0"}:
        raise HTTPException(400, "version must be v1 or v2")
    passport = build_passport(
        sealed=sealed,
        keyring=state.keyring,
        audit=state.engine.context.audit,
        lifecycle_state=lifecycle_state,
        grant=grant,
        grant_store=state.engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=outcome_proof,
        assessment=assessment,
    )
    if fmt == "html":
        from fastapi.responses import HTMLResponse

        return HTMLResponse(render_passport_html(passport))
    if fmt == "markdown":
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(render_passport_markdown(passport))
    return passport.model_dump(mode="json")


@router.get("/refunds/{manifest_id}/evidence-pack")
def refund_evidence_pack(
    org_id: str,
    manifest_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """A self-contained, offline-verifiable Evidence Pack (Phase 24) for
    this refund: a recipient with only this one JSON document -- no
    account on this deployment, no access to this organization's store --
    can independently re-verify the seal, grant signature, passport
    content hash, and audit-slice self-consistency. See
    docs/portable-evidence.md."""
    state = resolve_org_runtime(request, user, org_id)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    grant_ids = state.grants_by_manifest.get(manifest_id, [])
    grant = state.grants[grant_ids[-1]] if grant_ids else None
    lifecycle_state = state.engine.get_lifecycle_state(manifest_id).value
    passport = build_passport_v2(
        sealed=sealed,
        keyring=state.keyring,
        audit=state.engine.context.audit,
        lifecycle_state=lifecycle_state,
        grant=grant,
        grant_store=state.engine.context.grant_store,
        commit_result=state.commit_results.get(manifest_id),
        outcome_proof=state.outcome_proofs.get(manifest_id),
        assessment=state.assessments.get(manifest_id),
        tenant_id=org_id,
    )
    pack = build_evidence_pack(
        passport=passport,
        sealed_manifest=sealed,
        audit=state.engine.context.audit,
        keyring=state.keyring,
        grant=grant,
    )
    return pack.model_dump(mode="json")


@router.get("/audit")
def search_audit(
    org_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
    manifest_id: str | None = Query(default=None, max_length=128),
    q: str | None = Query(default=None, max_length=200),
    event_type: str | None = Query(default=None, max_length=256),
    decision: str | None = Query(default=None, max_length=256),
) -> dict[str, Any]:
    """Search one organization's append-only, hash-chained audit trail."""
    state = resolve_org_runtime(request, user, org_id)
    events = (
        state.engine.context.audit.events_for_manifest(manifest_id)
        if manifest_id is not None
        else state.engine.context.audit.all_events()
    )
    if event_type:
        normalized_event_type = event_type.strip().casefold()
        events = [event for event in events if event.event_type.casefold() == normalized_event_type]
    if decision:
        normalized_decision = decision.strip().casefold()
        events = [event for event in events if event.decision.casefold() == normalized_decision]
    if q:
        needle = q.strip().casefold()
        if needle:
            events = [
                event
                for event in events
                if needle
                in " ".join(
                    [
                        event.event_type,
                        event.decision,
                        event.manifest_id or "",
                        event.manifest_hash or "",
                        event.grant_id or "",
                        event.actor_id or "",
                        event.from_state or "",
                        event.to_state or "",
                        *event.metadata.keys(),
                        *event.metadata.values(),
                    ]
                ).casefold()
            ]
    return {"events": [e.model_dump(mode="json") for e in events]}


@router.get("/audit/verify")
def verify_audit(
    org_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    state = resolve_org_runtime(request, user, org_id)
    try:
        state.engine.context.audit.verify_chain()
        return {"verified": True}
    except KarmaSakshiError as exc:
        raise HTTPException(500, f"audit chain verification failed: {exc}") from exc


__all__ = ["router"]
