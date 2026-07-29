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

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.adapters.payment_simulator import PaymentRequest
from karmasakshi.compensation import build_compensation_manifest
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import KarmaSakshiError
from karmasakshi.gateway.api import require_gateway_session, resolve_org_runtime
from karmasakshi.gateway.models import GatewayUser
from karmasakshi.gateway.schemas import validate_principal_safe_id
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.intelligence.policy import IntelligencePolicy, build_policy_bundle
from karmasakshi.passports import (
    build_passport,
    build_passport_v2,
    render_passport_html,
    render_passport_markdown,
    render_passport_v2_html,
    render_passport_v2_markdown,
)
from karmasakshi.policy import seal_policy_bundle
from karmasakshi.portable import build_evidence_pack

router = APIRouter(prefix="/gateway/organizations/{org_id}", tags=["gateway-refunds"])

_PAYMENT_ADAPTER_ID = "payment.simulator"


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
    now = datetime.now(timezone.utc)
    policy = IntelligencePolicy(
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


@router.post("/refunds/propose")
def propose_refund(
    org_id: str,
    body: RefundProposeIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """Propose an exact refund effect: prepare + seal + run the
    (advisory) Effect Intelligence Engine risk assessment."""
    state = resolve_org_runtime(request, user, org_id)
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
    try:
        manifest = state.engine.prepare(adapter, payment_request, context=None)
        sealed = state.engine.seal(manifest, state.signing_key)
        assessment = state.engine.assess(manifest)
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.sealed_manifests[manifest.manifest_id] = sealed
    state.assessments[manifest.manifest_id] = assessment
    return {
        "manifest_id": manifest.manifest_id,
        "manifest_hash": sealed.seal.manifest_hash,
        "assessment": {
            "score": assessment.score,
            "risk_level": assessment.risk_level.value,
            "recommendation": assessment.recommendation.value,
            "required_human_approvals": assessment.required_human_approvals,
            "explanation": assessment.explanation,
        },
    }


@router.post("/refunds/{manifest_id}/approve")
def approve_refund(
    org_id: str,
    manifest_id: str,
    body: RefundApproveIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> dict[str, Any]:
    """Human approval: issues an ExecutionGrant. The approver is the
    authenticated session user (never a client-supplied identity claim).
    Invariant #30 -- ``authorize()`` structurally rejects an agent
    issuer, so the approver can never be the refund agent itself."""
    state = resolve_org_runtime(request, user, org_id)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    policy_bundle = None
    bundle_id = body.policy_bundle_id or state.active_policy_bundle_id
    if bundle_id is not None:
        policy_bundle = state.policy_bundles.get(bundle_id)
        if policy_bundle is None:
            raise HTTPException(404, f"policy bundle {bundle_id!r} not found")
    now = datetime.now(timezone.utc)
    try:
        grant = state.engine.authorize(
            sealed,
            issuer=_human(user.user_id),
            subject=sealed.manifest.actor,
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
    return {"grant_id": grant.grant_id, "policy_bundle_hash": grant.policy_bundle_hash}


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
    evaluation simplicity. Reports the honest triad -- attempted vs.
    succeeded are independent booleans; a settled payment's compensation
    is truthfully refused (`succeeded=False`), never silently upgraded.
    The approver is the authenticated session user."""
    state = resolve_org_runtime(request, user, org_id)
    original = state.sealed_manifests.get(manifest_id)
    original_commit = state.commit_results.get(manifest_id)
    if original is None or original_commit is None:
        raise HTTPException(404, "manifest or commit result not found")
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
    manifest_id: str | None = None,
) -> dict[str, Any]:
    """The organization's full audit trail, optionally filtered to one
    manifest -- append-only and hash-chained (invariant #22)."""
    state = resolve_org_runtime(request, user, org_id)
    events = (
        state.engine.context.audit.events_for_manifest(manifest_id)
        if manifest_id is not None
        else state.engine.context.audit.all_events()
    )
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
