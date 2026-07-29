"""JSON API routes for the control plane."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from karmasakshi.adapters.email_sandbox import EmailRequest
from karmasakshi.adapters.payment_simulator import PaymentRequest
from karmasakshi.adapters.sqlite_db import RowEffectRequest
from karmasakshi.api.auth import is_dev_mode, require_auth
from karmasakshi.api.schemas import (
    ApprovalPolicyBundleCreateIn,
    ApprovalStatementIn,
    ApproveIn,
    AssessIn,
    CausalLinkIn,
    DenyIn,
    ExecuteIn,
    ManifestSummary,
    PolicyBundleCreateIn,
    PrepareRequestIn,
    QuorumEvaluateIn,
    QuorumGrantIn,
    SeparationOfDutyPolicyBundleCreateIn,
)
from karmasakshi.api.state import ApiState
from karmasakshi.approval import (
    ApprovalPolicy,
    approval_policy_from_bundle_payload,
    build_approval_policy_bundle,
    evaluate_quorum,
    sign_approval_statement,
)
from karmasakshi.causal.graph import CausalEffectGraph
from karmasakshi.domain.common import Principal
from karmasakshi.duty import SeparationOfDutyPolicy, build_separation_of_duty_policy_bundle
from karmasakshi.duty.roles import RoleAssignment
from karmasakshi.errors import KarmaSakshiError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.intelligence import AssessmentFacts, IntelligencePolicy, derive_facts_from_audit
from karmasakshi.intelligence.policy import build_policy_bundle
from karmasakshi.passports import build_passport, render_passport_html, render_passport_markdown
from karmasakshi.policy import seal_policy_bundle, verify_policy_bundle

router = APIRouter()

_ADAPTER_KEY = {"sqlite": "sqlite.row", "email": "email.sandbox", "payment": "payment.simulator"}


def _state(request: Request) -> ApiState:
    return request.app.state.karmasakshi  # type: ignore[no-any-return]


def _parse_role_assignment(manifest_hash: str, roles: list[str]) -> RoleAssignment | None:
    """Parse ``"role_name:principal_id"`` entries into a
    :class:`RoleAssignment`, or ``None`` if ``roles`` is empty."""
    if not roles:
        return None
    assignments: list[tuple[str, str]] = []
    for entry in roles:
        role, sep, principal_id = entry.partition(":")
        if not sep:
            raise HTTPException(422, f"role entry must be 'role_name:principal_id', got {entry!r}")
        assignments.append((role, principal_id))
    return RoleAssignment(manifest_hash=manifest_hash, assignments=tuple(assignments))


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def ready(request: Request) -> dict[str, Any]:
    state = _state(request)
    try:
        state.engine.context.audit.verify_chain()
        audit_ok = True
    except KarmaSakshiError:
        audit_ok = False
    return {
        "status": "ready" if audit_ok else "degraded",
        "dev_mode": is_dev_mode(),
        "kill_switch_engaged": state.kill_switch_engaged,
        "audit_chain_verified": audit_ok,
    }


@router.post("/principals", dependencies=[Depends(require_auth)])
def register_principal(body: dict[str, Any], request: Request) -> dict[str, str]:
    state = _state(request)
    principal = Principal.model_validate(body)
    state.principals[principal.principal_id] = principal
    return {"principal_id": principal.principal_id}


@router.get("/principals", dependencies=[Depends(require_auth)])
def list_principals(request: Request) -> dict[str, Any]:
    state = _state(request)
    return {"principals": [p.model_dump(mode="json") for p in state.principals.values()]}


def _build_request(adapter_choice: str, body: PrepareRequestIn) -> Any:
    actor = Principal(**body.actor.model_dump())
    principal = Principal(**body.principal.model_dump())
    f = body.fields
    if adapter_choice == "sqlite":
        return RowEffectRequest(
            operation=f["operation"],  # type: ignore[arg-type]
            row_id=str(f["row_id"]),
            actor=actor,
            principal=principal,
            new_balance=f.get("new_balance"),  # type: ignore[arg-type]
            idempotency_key=body.idempotency_key,
            ttl_seconds=body.ttl_seconds,
        )
    if adapter_choice == "email":
        recipients = str(f["recipients"]).split(",")
        return EmailRequest(
            actor=actor,
            principal=principal,
            recipients=tuple(recipients),
            subject=str(f["subject"]),
            body=str(f["body"]),
            idempotency_key=body.idempotency_key,
            ttl_seconds=body.ttl_seconds,
        )
    if adapter_choice == "payment":
        return PaymentRequest(
            actor=actor,
            principal=principal,
            source_account=str(f["source_account"]),
            beneficiary=str(f["beneficiary"]),
            amount_minor_units=int(f["amount_minor_units"]),  # type: ignore[arg-type]
            currency=str(f.get("currency", "INR")),
            reference=str(f["reference"]),
            fee_minor_units=int(f.get("fee_minor_units", 0)),  # type: ignore[arg-type]
            idempotency_key=body.idempotency_key,
            ttl_seconds=body.ttl_seconds,
        )
    raise HTTPException(400, f"unknown adapter {adapter_choice!r}")


@router.post("/manifests/prepare", dependencies=[Depends(require_auth)])
def prepare_manifest(body: PrepareRequestIn, request: Request) -> dict[str, Any]:
    state = _state(request)
    adapter = state.adapters[_ADAPTER_KEY[body.adapter]]
    req = _build_request(body.adapter, body)
    try:
        manifest = state.engine.prepare(adapter, req, context=None)
        sealed = state.engine.seal(manifest, state.signing_key)
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.sealed_manifests[manifest.manifest_id] = sealed
    return {"manifest_id": manifest.manifest_id, "manifest_hash": sealed.seal.manifest_hash}


@router.get("/manifests", dependencies=[Depends(require_auth)])
def list_manifests(request: Request) -> dict[str, Any]:
    state = _state(request)
    summaries = []
    for mid, sealed in state.sealed_manifests.items():
        summaries.append(
            ManifestSummary(
                manifest_id=mid,
                manifest_hash=sealed.seal.manifest_hash,
                effect_type=sealed.manifest.effect_type,
                target_resource=sealed.manifest.target_resource,
                lifecycle_state=state.engine.get_lifecycle_state(mid).value,
                risk=sealed.manifest.risk.value,
                reversibility=sealed.manifest.reversibility.value,
                created_at=sealed.manifest.created_at,
            )
        )
    return {"manifests": [s.model_dump(mode="json") for s in summaries]}


@router.get("/manifests/{manifest_id}", dependencies=[Depends(require_auth)])
def get_manifest(manifest_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    return {
        "manifest": sealed.manifest.model_dump(mode="json"),
        "seal": sealed.seal.model_dump(mode="json"),
        "lifecycle_state": state.engine.get_lifecycle_state(manifest_id).value,
        "grant_ids": state.grants_by_manifest.get(manifest_id, []),
    }


@router.post("/manifests/{manifest_id}/approve", dependencies=[Depends(require_auth)])
def approve_manifest(manifest_id: str, body: ApproveIn, request: Request) -> dict[str, Any]:
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    policy_bundle = None
    if body.policy_bundle_id is not None:
        policy_bundle = state.policy_bundles.get(body.policy_bundle_id)
        if policy_bundle is None:
            raise HTTPException(404, f"policy bundle {body.policy_bundle_id!r} not found")
    separation_policy_bundle = None
    if body.separation_policy_bundle_id is not None:
        separation_policy_bundle = state.policy_bundles.get(body.separation_policy_bundle_id)
        if separation_policy_bundle is None:
            raise HTTPException(
                404, f"separation policy bundle {body.separation_policy_bundle_id!r} not found"
            )
    role_assignment = _parse_role_assignment(sealed.seal.manifest_hash, body.roles)
    now = datetime.now(timezone.utc)
    try:
        grant = state.engine.authorize(
            sealed,
            issuer=Principal(**body.issuer.model_dump()),
            subject=Principal(**body.subject.model_dump()),
            audience=(
                tuple(body.audience) if body.audience else (sealed.manifest.adapter.adapter_id,)
            ),
            allowed_effect_types=(sealed.manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(seconds=body.ttl_seconds),
            signing_key=state.signing_key,
            max_uses=body.max_uses,
            policy_bundle=policy_bundle,
            separation_policy_bundle=separation_policy_bundle,
            role_assignment=role_assignment,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(403, str(exc)) from exc
    state.register_grant(manifest_id, grant)
    return {"grant_id": grant.grant_id, "policy_bundle_hash": grant.policy_bundle_hash}


@router.post("/manifests/{manifest_id}/deny", dependencies=[Depends(require_auth)])
def deny_manifest(manifest_id: str, body: DenyIn, request: Request) -> dict[str, Any]:
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    state.engine.context.audit.record(
        event_type="manifest.authorization_denied",
        decision="denied",
        manifest_id=manifest_id,
        manifest_hash=sealed.seal.manifest_hash,
        metadata={"reason": body.reason[:200]},
    )
    return {"manifest_id": manifest_id, "denied": True, "reason": body.reason}


@router.post("/manifests/{manifest_id}/assess", dependencies=[Depends(require_auth)])
def assess_manifest(manifest_id: str, body: AssessIn, request: Request) -> dict[str, Any]:
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    if body.from_audit_history:
        facts = derive_facts_from_audit(
            state.engine.context.audit,
            sealed.manifest,
            delegation_depth=body.delegation_depth,
            provider_idempotent=body.provider_idempotent,
            compensation_feasible=body.compensation_feasible,
            cross_tenant=body.cross_tenant,
            unusual_parameter_change=body.unusual_parameter_change,
            extra_policy_violations=tuple(body.policy_violations),
        )
    else:
        facts = AssessmentFacts(
            delegation_depth=body.delegation_depth,
            historical_recurrence_count=body.historical_recurrence_count,
            historical_failure_count=body.historical_failure_count,
            provider_idempotent=body.provider_idempotent,
            compensation_feasible=body.compensation_feasible,
            cross_tenant=body.cross_tenant,
            unusual_parameter_change=body.unusual_parameter_change,
            policy_violations=tuple(body.policy_violations),
        )
    try:
        assessment = state.engine.assess(sealed.manifest, facts)
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.assessments[manifest_id] = assessment
    return assessment.model_dump(mode="json")


@router.get("/manifests/{manifest_id}/assessment", dependencies=[Depends(require_auth)])
def get_assessment(manifest_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    assessment = state.assessments.get(manifest_id)
    if assessment is None:
        raise HTTPException(404, "no assessment recorded for this manifest")
    return assessment.model_dump(mode="json")


@router.post("/policy/bundles", dependencies=[Depends(require_auth)])
def create_policy_bundle(body: PolicyBundleCreateIn, request: Request) -> dict[str, Any]:
    """Build, sign, and store a policy bundle (extreme-v2 Phase 2). The
    issuer must be a human or service principal -- see
    docs/policy-bundles.md."""
    state = _state(request)
    now = datetime.now(timezone.utc)
    policy = IntelligencePolicy(
        block_threshold=body.block_threshold,
        review_threshold=body.review_threshold,
        max_delegation_depth=body.max_delegation_depth,
        restricted_effect_types=tuple(body.restricted_effect_types),
        sensitive_target_patterns=tuple(body.sensitive_target_patterns),
    )
    try:
        bundle = build_policy_bundle(
            policy,
            bundle_id=body.bundle_id,
            bundle_version=body.bundle_version,
            issuer=Principal(**body.issuer.model_dump()),
            created_at=now,
            effective_from=now,
            effective_until=now + timedelta(seconds=body.effective_seconds),
            tenant_id=body.tenant_id,
        )
        sealed = seal_policy_bundle(bundle, state.signing_key)
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.policy_bundles[body.bundle_id] = sealed
    return sealed.model_dump(mode="json")


@router.get("/policy/bundles/{bundle_id}", dependencies=[Depends(require_auth)])
def get_policy_bundle(bundle_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    sealed = state.policy_bundles.get(bundle_id)
    if sealed is None:
        raise HTTPException(404, "policy bundle not found")
    return sealed.model_dump(mode="json")


@router.post("/policy/bundles/{bundle_id}/verify", dependencies=[Depends(require_auth)])
def verify_policy_bundle_route(bundle_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    sealed = state.policy_bundles.get(bundle_id)
    if sealed is None:
        raise HTTPException(404, "policy bundle not found")
    try:
        verify_policy_bundle(sealed, state.keyring, now=datetime.now(timezone.utc))
    except KarmaSakshiError as exc:
        raise HTTPException(422, f"policy bundle verification failed: {exc}") from exc
    return {"bundle_id": bundle_id, "verified": True}


@router.post("/policy/approval-bundles", dependencies=[Depends(require_auth)])
def create_approval_policy_bundle(
    body: ApprovalPolicyBundleCreateIn, request: Request
) -> dict[str, Any]:
    """Build, sign, and store an approval (quorum) policy bundle
    (``policy_type == "approval.v1"``). Shares storage with
    ``/policy/bundles`` -- both are ``PolicyBundle`` envelopes,
    distinguished by ``policy_type``. See docs/multi-party-authorization.md.
    """
    state = _state(request)
    now = datetime.now(timezone.utc)
    policy = ApprovalPolicy(
        required_approvals=body.required_approvals,
        required_roles=tuple(body.required_roles),
        forbid_proposer_as_approver=body.forbid_proposer_as_approver,
        forbid_subject_as_approver=body.forbid_subject_as_approver,
        veto_on_any_dissent=body.veto_on_any_dissent,
        cooling_off_seconds=body.cooling_off_seconds,
    )
    try:
        bundle = build_approval_policy_bundle(
            policy,
            bundle_id=body.bundle_id,
            bundle_version=body.bundle_version,
            issuer=Principal(**body.issuer.model_dump()),
            created_at=now,
            effective_from=now,
            effective_until=now + timedelta(seconds=body.effective_seconds),
            tenant_id=body.tenant_id,
        )
        sealed = seal_policy_bundle(bundle, state.signing_key)
    except (KarmaSakshiError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    state.policy_bundles[body.bundle_id] = sealed
    return sealed.model_dump(mode="json")


@router.post("/policy/separation-bundles", dependencies=[Depends(require_auth)])
def create_separation_policy_bundle(
    body: SeparationOfDutyPolicyBundleCreateIn, request: Request
) -> dict[str, Any]:
    """Build, sign, and store a separation-of-duty policy bundle
    (``policy_type == "separation.v1"``, extreme-v2 Phase 4). Shares
    storage with ``/policy/bundles`` -- see docs/separation-of-duties.md.
    """
    state = _state(request)
    now = datetime.now(timezone.utc)
    pairs: list[tuple[str, str]] = []
    for entry in body.forbidden_role_pairs:
        role_a, sep, role_b = entry.partition(":")
        if not sep:
            raise HTTPException(
                422, f"forbidden_role_pairs entry must be 'role_a:role_b', got {entry!r}"
            )
        pairs.append((role_a, role_b))
    policy = (
        SeparationOfDutyPolicy(forbidden_role_pairs=tuple(pairs))
        if pairs
        else SeparationOfDutyPolicy()
    )
    try:
        bundle = build_separation_of_duty_policy_bundle(
            policy,
            bundle_id=body.bundle_id,
            bundle_version=body.bundle_version,
            issuer=Principal(**body.issuer.model_dump()),
            created_at=now,
            effective_from=now,
            effective_until=now + timedelta(seconds=body.effective_seconds),
            tenant_id=body.tenant_id,
        )
        sealed = seal_policy_bundle(bundle, state.signing_key)
    except (KarmaSakshiError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    state.policy_bundles[body.bundle_id] = sealed
    return sealed.model_dump(mode="json")


@router.post("/manifests/{manifest_id}/approvals", dependencies=[Depends(require_auth)])
def submit_approval(
    manifest_id: str, body: ApprovalStatementIn, request: Request
) -> dict[str, Any]:
    """Record one approval or dissent statement for a manifest.

    Honesty note: this reference control plane signs every approval
    statement with its own single service signing key (the same key used
    for manifests, grants, and policy bundles elsewhere in this API) --
    it does not hold a distinct private key per human approver. The
    ``approver`` identity is still recorded and enforced (duplicate/self/
    subject-approver rejection all still apply), but the cryptographic
    signature does not by itself distinguish *which* approver submitted
    it the way independently-held keys would in a production deployment
    (see docs/multi-party-authorization.md and the CLI, where each
    workspace key genuinely is distinct).
    """
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    approval_bundle = state.policy_bundles.get(body.approval_policy_bundle_id)
    if approval_bundle is None:
        raise HTTPException(
            404, f"approval policy bundle {body.approval_policy_bundle_id!r} not found"
        )
    try:
        statement = sign_approval_statement(
            statement_id=str(uuid.uuid4()),
            manifest_hash=sealed.seal.manifest_hash,
            approval_policy_bundle_hash=approval_bundle.seal.bundle_hash,
            approver=Principal(**body.approver.model_dump()),
            decision=body.decision,
            signing_key=state.signing_key,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds),
            nonce=str(uuid.uuid4()),
            role=body.role,
            reason=body.reason,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.approval_statements.setdefault(manifest_id, []).append(statement)
    return statement.model_dump(mode="json")


@router.get("/manifests/{manifest_id}/approvals", dependencies=[Depends(require_auth)])
def list_approvals(manifest_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    statements = state.approval_statements.get(manifest_id, [])
    return {"statements": [s.model_dump(mode="json") for s in statements]}


@router.post("/manifests/{manifest_id}/approvals/evaluate", dependencies=[Depends(require_auth)])
def evaluate_approvals(
    manifest_id: str, body: QuorumEvaluateIn, request: Request
) -> dict[str, Any]:
    """Dry-run quorum evaluation: does not issue a grant."""
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    approval_bundle = state.policy_bundles.get(body.approval_policy_bundle_id)
    if approval_bundle is None:
        raise HTTPException(
            404, f"approval policy bundle {body.approval_policy_bundle_id!r} not found"
        )
    policy = approval_policy_from_bundle_payload(approval_bundle.bundle.payload)
    statements = tuple(state.approval_statements.get(manifest_id, []))
    result = evaluate_quorum(
        statements,
        policy,
        manifest_hash=sealed.seal.manifest_hash,
        approval_policy_bundle_hash=approval_bundle.seal.bundle_hash,
        keyring=state.keyring,
        proposer=Principal(**body.proposer.model_dump()),
        subject=Principal(**body.subject.model_dump()),
        now=datetime.now(timezone.utc),
    )
    return result.model_dump(mode="json")


@router.post("/manifests/{manifest_id}/approve-with-quorum", dependencies=[Depends(require_auth)])
def approve_with_quorum(manifest_id: str, body: QuorumGrantIn, request: Request) -> dict[str, Any]:
    """Issue an ExecutionGrant only if the manifest's stored approval
    statements satisfy the referenced approval policy bundle's quorum."""
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    approval_bundle = state.policy_bundles.get(body.approval_policy_bundle_id)
    if approval_bundle is None:
        raise HTTPException(
            404, f"approval policy bundle {body.approval_policy_bundle_id!r} not found"
        )
    policy_bundle = None
    if body.policy_bundle_id is not None:
        policy_bundle = state.policy_bundles.get(body.policy_bundle_id)
        if policy_bundle is None:
            raise HTTPException(404, f"policy bundle {body.policy_bundle_id!r} not found")
    separation_policy_bundle = None
    if body.separation_policy_bundle_id is not None:
        separation_policy_bundle = state.policy_bundles.get(body.separation_policy_bundle_id)
        if separation_policy_bundle is None:
            raise HTTPException(
                404, f"separation policy bundle {body.separation_policy_bundle_id!r} not found"
            )
    role_assignment = _parse_role_assignment(sealed.seal.manifest_hash, body.roles)
    statements = tuple(state.approval_statements.get(manifest_id, []))
    now = datetime.now(timezone.utc)
    try:
        grant = state.engine.authorize_with_quorum(
            sealed,
            statements=statements,
            approval_policy_bundle=approval_bundle,
            proposer=Principal(**body.proposer.model_dump()),
            subject=Principal(**body.subject.model_dump()),
            grant_issuer=Principal(**body.grant_issuer.model_dump()),
            audience=(
                tuple(body.audience) if body.audience else (sealed.manifest.adapter.adapter_id,)
            ),
            allowed_effect_types=(sealed.manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(seconds=body.ttl_seconds),
            signing_key=state.signing_key,
            max_uses=body.max_uses,
            policy_bundle=policy_bundle,
            separation_policy_bundle=separation_policy_bundle,
            role_assignment=role_assignment,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(403, str(exc)) from exc
    state.register_grant(manifest_id, grant)
    return {"grant_id": grant.grant_id, "approval_set_hash": grant.approval_set_hash}


@router.post("/grants/{grant_id}/revoke", dependencies=[Depends(require_auth)])
def revoke_grant(grant_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    grant = state.grants.get(grant_id)
    if grant is None:
        raise HTTPException(404, "grant not found")
    manifest_id = next(
        (mid for mid, ids in state.grants_by_manifest.items() if grant_id in ids), grant_id
    )
    stopped = state.engine.revoke(grant, manifest_id, revoked_by=grant.issuer)
    return {"grant_id": grant_id, "stopped_at_safepoint": stopped}


@router.post("/manifests/{manifest_id}/execute", dependencies=[Depends(require_auth)])
def execute_manifest(manifest_id: str, body: ExecuteIn, request: Request) -> dict[str, Any]:
    state = _state(request)
    if state.kill_switch_engaged:
        raise HTTPException(503, "kill switch engaged; execution refused")
    sealed = state.sealed_manifests.get(manifest_id)
    grant = state.grants.get(body.grant_id)
    if sealed is None or grant is None:
        raise HTTPException(404, "manifest or grant not found")
    policy_bundle = None
    if body.policy_bundle_id is not None:
        policy_bundle = state.policy_bundles.get(body.policy_bundle_id)
        if policy_bundle is None:
            raise HTTPException(404, f"policy bundle {body.policy_bundle_id!r} not found")
    adapter = state.adapters[sealed.manifest.adapter.adapter_id]
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


@router.post("/manifests/{manifest_id}/verify", dependencies=[Depends(require_auth)])
def verify_manifest(manifest_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    result = state.commit_results.get(manifest_id)
    if sealed is None or result is None:
        raise HTTPException(404, "manifest or commit result not found")
    adapter = state.adapters[sealed.manifest.adapter.adapter_id]
    proof = state.engine.verify(sealed.manifest, result, adapter, context=None)
    state.outcome_proofs[manifest_id] = proof
    return {"matched_expected": proof.matched_expected, "detail": proof.detail}


@router.get("/audit", dependencies=[Depends(require_auth)])
def audit_timeline(request: Request) -> dict[str, Any]:
    state = _state(request)
    events = state.engine.context.audit.all_events()
    return {"events": [e.model_dump(mode="json") for e in events]}


@router.get("/audit/verify", dependencies=[Depends(require_auth)])
def audit_verify(request: Request) -> dict[str, Any]:
    state = _state(request)
    try:
        state.engine.context.audit.verify_chain()
        return {"verified": True}
    except KarmaSakshiError as exc:
        raise HTTPException(500, f"audit chain verification failed: {exc}") from exc


@router.post("/causal-links", dependencies=[Depends(require_auth)])
def record_causal_link(body: CausalLinkIn, request: Request) -> dict[str, Any]:
    """Sign and record a causal link between two manifests
    (extreme-v2 Phase 5, advisory only -- see docs/causal-effect-graphs.md).
    """
    state = _state(request)
    parent_sealed = state.sealed_manifests.get(body.parent_manifest_id)
    child_sealed = state.sealed_manifests.get(body.child_manifest_id)
    if parent_sealed is None or child_sealed is None:
        raise HTTPException(404, "parent or child manifest not found")
    try:
        link = state.engine.record_causal_link(
            parent_manifest_hash=parent_sealed.seal.manifest_hash,
            child_manifest_hash=child_sealed.seal.manifest_hash,
            relationship=body.relationship,
            recorded_by=Principal(**body.recorded_by.model_dump()),
            signing_key=state.signing_key,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.causal_links.append(link)
    return link.model_dump(mode="json")


@router.get("/causal-links", dependencies=[Depends(require_auth)])
def list_causal_links(request: Request) -> dict[str, Any]:
    state = _state(request)
    return {"links": [link.model_dump(mode="json") for link in state.causal_links]}


@router.post("/causal-links/verify", dependencies=[Depends(require_auth)])
def verify_causal_links(request: Request) -> dict[str, Any]:
    """Verify every causal link ever recorded in this control plane:
    every signature independently, and the whole graph for cycles."""
    state = _state(request)
    try:
        result = state.engine.verify_causal_graph(tuple(state.causal_links))
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {
        "verified": result.verified,
        "has_cycle": result.has_cycle,
        "invalid_link_ids": list(result.invalid_link_ids),
        "node_count": result.node_count,
        "edge_count": result.edge_count,
        "reason": result.reason,
    }


@router.get("/passports/{manifest_id}", dependencies=[Depends(require_auth)])
def get_passport(manifest_id: str, request: Request, fmt: str = "json") -> Any:
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    grant_ids = state.grants_by_manifest.get(manifest_id, [])
    grant = state.grants[grant_ids[-1]] if grant_ids else None
    causal_graph = (
        CausalEffectGraph(links=tuple(state.causal_links)) if state.causal_links else None
    )
    passport = build_passport(
        sealed=sealed,
        keyring=state.keyring,
        audit=state.engine.context.audit,
        lifecycle_state=state.engine.get_lifecycle_state(manifest_id).value,
        grant=grant,
        grant_store=state.engine.context.grant_store,
        commit_result=state.commit_results.get(manifest_id),
        outcome_proof=state.outcome_proofs.get(manifest_id),
        compensation_result=state.compensation_results.get(manifest_id),
        assessment=state.assessments.get(manifest_id),
        causal_graph=causal_graph,
    )
    if fmt == "html":
        from fastapi.responses import HTMLResponse

        return HTMLResponse(render_passport_html(passport))
    if fmt == "markdown":
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(render_passport_markdown(passport))
    return passport.model_dump(mode="json")


@router.get("/kill-switch", dependencies=[Depends(require_auth)])
def kill_switch_status(request: Request) -> dict[str, bool]:
    return {"engaged": _state(request).kill_switch_engaged}


@router.post("/kill-switch/engage", dependencies=[Depends(require_auth)])
def kill_switch_engage(request: Request) -> dict[str, bool]:
    state = _state(request)
    state.kill_switch_engaged = True
    return {"engaged": True}


@router.post("/kill-switch/disengage", dependencies=[Depends(require_auth)])
def kill_switch_disengage(request: Request) -> dict[str, bool]:
    state = _state(request)
    state.kill_switch_engaged = False
    return {"engaged": False}


__all__ = ["router"]
