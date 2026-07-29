"""JSON API routes for the control plane."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from karmasakshi.adapters.base import CompensationResult
from karmasakshi.adapters.email_sandbox import EmailRequest
from karmasakshi.adapters.payment_simulator import PaymentRequest
from karmasakshi.adapters.sqlite_db import RowEffectRequest
from karmasakshi.api.auth import is_dev_mode, require_auth
from karmasakshi.api.schemas import (
    ApprovalPolicyBundleCreateIn,
    ApprovalStatementIn,
    ApproveIn,
    AssessIn,
    CausalGraphCreateIn,
    CompensationAuthorizeIn,
    CompensationExecuteIn,
    DecisionEnvelopeCreateIn,
    DecisionEnvelopeSubstituteIn,
    DenyIn,
    ExecuteIn,
    ManifestSummary,
    ParameterConstraintIn,
    PolicyBundleCreateIn,
    PrepareRequestIn,
    QuorumEvaluateIn,
    QuorumGrantIn,
    SeparationOfDutyPolicyBundleCreateIn,
    WitnessEvaluateIn,
    WitnessStatementIn,
)
from karmasakshi.api.state import ApiState
from karmasakshi.approval import (
    ApprovalPolicy,
    approval_policy_from_bundle_payload,
    build_approval_policy_bundle,
    evaluate_quorum,
    sign_approval_statement,
)
from karmasakshi.causal import build_causal_graph, sign_causal_link
from karmasakshi.compensation import (
    build_compensation_manifest,
    build_compensation_passport,
)
from karmasakshi.domain.common import AdapterIdentity, MonetaryAmount, Principal
from karmasakshi.duty import SeparationOfDutyPolicy, build_separation_of_duty_policy_bundle
from karmasakshi.duty.roles import RoleAssignment
from karmasakshi.envelope import (
    ParameterConstraint,
    build_decision_envelope,
    enum_of,
    exact,
    integer_range,
    monetary_range,
    seal_decision_envelope,
    substitute_parameters,
    verify_decision_envelope,
)
from karmasakshi.errors import KarmaSakshiError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.intelligence import AssessmentFacts, IntelligencePolicy, derive_facts_from_audit
from karmasakshi.intelligence.policy import build_policy_bundle
from karmasakshi.passports import (
    build_passport,
    build_passport_v2,
    render_passport_html,
    render_passport_markdown,
    render_passport_v2_html,
    render_passport_v2_markdown,
)
from karmasakshi.policy import seal_policy_bundle, verify_policy_bundle
from karmasakshi.portable import EvidencePack, build_evidence_pack, verify_evidence_pack

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


@router.post("/causal-graphs", dependencies=[Depends(require_auth)])
def create_causal_graph(body: CausalGraphCreateIn, request: Request) -> dict[str, Any]:
    """Create a canonical DAG whose edges are independently signed."""
    state = _state(request)
    sealed_by_id = {}
    for manifest_id in body.manifest_ids:
        sealed = state.sealed_manifests.get(manifest_id)
        if sealed is None:
            raise HTTPException(404, f"manifest {manifest_id!r} not found")
        sealed_by_id[manifest_id] = sealed
    now = datetime.now(timezone.utc)
    try:
        links = tuple(
            sign_causal_link(
                parent_manifest_hash=sealed_by_id[edge.parent_manifest_id].seal.manifest_hash,
                child_manifest_hash=sealed_by_id[edge.child_manifest_id].seal.manifest_hash,
                relation=edge.relation,
                signing_key=state.signing_key,
                created_at=now,
            )
            for edge in body.edges
        )
        graph = build_causal_graph(
            node_manifest_hashes=tuple(
                sealed_by_id[manifest_id].seal.manifest_hash for manifest_id in body.manifest_ids
            ),
            links=links,
        )
        graph.verify(state.keyring)
    except KeyError as exc:
        raise HTTPException(
            422, f"causal edge references unlisted manifest {exc.args[0]!r}"
        ) from exc
    except (KarmaSakshiError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    state.causal_graphs[graph.graph_id] = graph
    state.engine.context.audit.record(
        event_type="causal_graph.created",
        decision="recorded",
        metadata={
            "graph_id": graph.graph_id,
            "graph_hash": graph.canonical_hash(),
            "node_count": str(len(graph.node_manifest_hashes)),
            "link_count": str(len(graph.links)),
        },
    )
    return graph.model_dump(mode="json") | {"graph_hash": graph.canonical_hash()}


@router.get("/causal-graphs/{graph_id}", dependencies=[Depends(require_auth)])
def get_causal_graph(graph_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    graph = state.causal_graphs.get(graph_id)
    if graph is None:
        raise HTTPException(404, "causal graph not found")
    try:
        graph.verify(state.keyring)
        verified = True
    except KarmaSakshiError:
        verified = False
    return graph.model_dump(mode="json") | {
        "graph_hash": graph.canonical_hash(),
        "roots": graph.roots(),
        "verified": verified,
    }


def _constraint_from_api(spec: ParameterConstraintIn) -> ParameterConstraint:
    if spec.kind == "exact":
        return exact(spec.exact_value)
    if spec.kind == "enum":
        if not spec.allowed_values:
            raise HTTPException(422, "enum constraints require allowed_values")
        return enum_of(*spec.allowed_values)
    if spec.kind == "integer_range":
        return integer_range(min_int=spec.min_int, max_int=spec.max_int)
    if spec.kind == "monetary_range":
        if not spec.currency:
            raise HTTPException(422, "monetary_range requires currency")
        return monetary_range(
            currency=spec.currency,
            min_minor_units=spec.min_minor_units,
            max_minor_units=spec.max_minor_units,
        )
    raise HTTPException(422, f"unknown constraint kind {spec.kind!r}")


@router.post("/decision-envelopes", dependencies=[Depends(require_auth)])
def create_decision_envelope(body: DecisionEnvelopeCreateIn, request: Request) -> dict[str, Any]:
    """Create and seal a constrained Decision Envelope."""
    state = _state(request)
    now = datetime.now(timezone.utc)
    try:
        constraints = {name: _constraint_from_api(spec) for name, spec in body.constraints.items()}
        max_cost = None
        if body.max_cost_currency is not None and body.max_cost_minor_units is not None:
            max_cost = MonetaryAmount(
                currency=body.max_cost_currency, minor_units=body.max_cost_minor_units
            )
        graph_hash = None
        if body.causal_graph_id is not None:
            graph = state.causal_graphs.get(body.causal_graph_id)
            if graph is None:
                raise HTTPException(404, f"causal graph {body.causal_graph_id!r} not found")
            graph.verify(state.keyring)
            graph_hash = graph.canonical_hash()
        envelope = build_decision_envelope(
            envelope_id=body.envelope_id,
            effect_type=body.effect_type,
            adapter=AdapterIdentity(
                adapter_id=body.adapter_id, adapter_version=body.adapter_version
            ),
            target_resources=tuple(body.target_resources),
            parameter_constraints=constraints,
            issuer=Principal(**body.issuer.model_dump()),
            not_before=now,
            expires_at=now + timedelta(seconds=body.ttl_seconds),
            signing_key_id=state.signing_key.key_id,
            created_at=now,
            forbid_unknown_parameters=body.forbid_unknown_parameters,
            require_all_constrained_parameters=body.require_all_constrained_parameters,
            max_estimated_cost=max_cost,
            causal_graph_hash=graph_hash,
        )
        envelope = seal_decision_envelope(envelope, state.signing_key)
        verify_decision_envelope(envelope, state.keyring, now=now)
    except HTTPException:
        raise
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.decision_envelopes[envelope.envelope_id] = envelope
    state.engine.context.audit.record(
        event_type="decision_envelope.created",
        decision="recorded",
        metadata={
            "envelope_id": envelope.envelope_id,
            "envelope_hash": envelope.canonical_hash(),
        },
    )
    return envelope.model_dump(mode="json") | {"envelope_hash": envelope.canonical_hash()}


@router.get("/decision-envelopes/{envelope_id}", dependencies=[Depends(require_auth)])
def get_decision_envelope(envelope_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    envelope = state.decision_envelopes.get(envelope_id)
    if envelope is None:
        raise HTTPException(404, "decision envelope not found")
    try:
        verify_decision_envelope(envelope, state.keyring, now=datetime.now(timezone.utc))
        verified = True
    except KarmaSakshiError:
        verified = False
    return envelope.model_dump(mode="json") | {
        "envelope_hash": envelope.canonical_hash(),
        "verified": verified,
    }


@router.post("/decision-envelopes/{envelope_id}/substitute", dependencies=[Depends(require_auth)])
def substitute_decision_envelope(
    envelope_id: str, body: DecisionEnvelopeSubstituteIn, request: Request
) -> dict[str, Any]:
    state = _state(request)
    envelope = state.decision_envelopes.get(envelope_id)
    if envelope is None:
        raise HTTPException(404, "decision envelope not found")
    try:
        verify_decision_envelope(envelope, state.keyring, now=datetime.now(timezone.utc))
        resolved = substitute_parameters(envelope, body.choices)
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"envelope_id": envelope_id, "parameters": resolved}


@router.post("/manifests/{manifest_id}/approve", dependencies=[Depends(require_auth)])
def approve_manifest(manifest_id: str, body: ApproveIn, request: Request) -> dict[str, Any]:
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    if body.decision_envelope_id is not None and body.causal_graph_id is not None:
        raise HTTPException(422, "decision_envelope_id and causal_graph_id are mutually exclusive")
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
    issuer = Principal(**body.issuer.model_dump())
    subject = Principal(**body.subject.model_dump())
    grant_audience = (
        tuple(body.audience) if body.audience else (sealed.manifest.adapter.adapter_id,)
    )
    expires_at = now + timedelta(seconds=body.ttl_seconds)
    try:
        if body.decision_envelope_id is not None:
            envelope = state.decision_envelopes.get(body.decision_envelope_id)
            if envelope is None:
                raise HTTPException(
                    404, f"decision envelope {body.decision_envelope_id!r} not found"
                )
            grant = state.engine.authorize_with_envelope(
                sealed,
                envelope,
                issuer=issuer,
                subject=subject,
                audience=grant_audience,
                allowed_effect_types=(sealed.manifest.effect_type,),
                scope=ScopeConstraints(),
                not_before=now,
                expires_at=expires_at,
                signing_key=state.signing_key,
                max_uses=body.max_uses,
                policy_bundle=policy_bundle,
                separation_policy_bundle=separation_policy_bundle,
                role_assignment=role_assignment,
            )
        elif body.causal_graph_id is not None:
            graph = state.causal_graphs.get(body.causal_graph_id)
            if graph is None:
                raise HTTPException(404, f"causal graph {body.causal_graph_id!r} not found")
            grant = state.engine.authorize_plan(
                sealed,
                graph,
                issuer=issuer,
                subject=subject,
                audience=grant_audience,
                allowed_effect_types=(sealed.manifest.effect_type,),
                scope=ScopeConstraints(),
                not_before=now,
                expires_at=expires_at,
                signing_key=state.signing_key,
                max_uses=body.max_uses,
                policy_bundle=policy_bundle,
                separation_policy_bundle=separation_policy_bundle,
                role_assignment=role_assignment,
            )
        else:
            grant = state.engine.authorize(
                sealed,
                issuer=issuer,
                subject=subject,
                audience=grant_audience,
                allowed_effect_types=(sealed.manifest.effect_type,),
                scope=ScopeConstraints(),
                not_before=now,
                expires_at=expires_at,
                signing_key=state.signing_key,
                max_uses=body.max_uses,
                policy_bundle=policy_bundle,
                separation_policy_bundle=separation_policy_bundle,
                role_assignment=role_assignment,
            )
    except HTTPException:
        raise
    except KarmaSakshiError as exc:
        raise HTTPException(403, str(exc)) from exc
    state.register_grant(manifest_id, grant)
    return {
        "grant_id": grant.grant_id,
        "policy_bundle_hash": grant.policy_bundle_hash,
        "decision_envelope_hash": grant.decision_envelope_hash,
        "causal_graph_hash": grant.causal_graph_hash,
    }


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


@router.post("/manifests/{manifest_id}/witnesses", dependencies=[Depends(require_auth)])
def submit_witness(manifest_id: str, body: WitnessStatementIn, request: Request) -> dict[str, Any]:
    """Record one independent witness statement for a verified outcome digest.

    Honesty note: like approvals, this reference control plane signs with
    the single service key; production deployments should use per-witness
    keys (see CLI ``karmasakshi witness sign``).
    """
    from karmasakshi.witness import WitnessPolicy, sign_witness_statement

    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    policy = WitnessPolicy(required_witnesses=body.required_witnesses)
    try:
        statement = sign_witness_statement(
            statement_id=str(uuid.uuid4()),
            manifest_hash=sealed.seal.manifest_hash,
            witness_policy_hash=policy.policy_hash(),
            observed_after_state_digest=body.observed_after_state_digest,
            matched_expected=body.matched_expected,
            witness=Principal(**body.witness.model_dump()),
            signing_key=state.signing_key,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds),
            nonce=str(uuid.uuid4()),
        )
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.witness_statements.setdefault(manifest_id, []).append(statement)
    return statement.model_dump(mode="json")


@router.get("/manifests/{manifest_id}/witnesses", dependencies=[Depends(require_auth)])
def list_witnesses(manifest_id: str, request: Request) -> dict[str, Any]:
    state = _state(request)
    statements = state.witness_statements.get(manifest_id, [])
    return {"statements": [s.model_dump(mode="json") for s in statements]}


@router.post("/manifests/{manifest_id}/witnesses/evaluate", dependencies=[Depends(require_auth)])
def evaluate_witnesses(
    manifest_id: str, body: WitnessEvaluateIn, request: Request
) -> dict[str, Any]:
    """Evaluate (optionally assert) independent witness quorum for PROVE time."""
    from karmasakshi.witness import WitnessPolicy

    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    policy = WitnessPolicy(required_witnesses=body.required_witnesses)
    statements = tuple(state.witness_statements.get(manifest_id, []))
    actor = Principal(**body.actor.model_dump())
    subject = Principal(**body.subject.model_dump())
    try:
        if body.assert_quorum:
            result = state.engine.prove_with_witness_quorum(
                sealed,
                statements=statements,
                policy=policy,
                expected_after_state_digest=body.expected_after_state_digest,
                actor=actor,
                subject=subject,
            )
        else:
            result = state.engine.evaluate_witnesses(
                sealed,
                statements=statements,
                policy=policy,
                expected_after_state_digest=body.expected_after_state_digest,
                actor=actor,
                subject=subject,
            )
    except KarmaSakshiError as exc:
        raise HTTPException(403, str(exc)) from exc
    return result.model_dump(mode="json")


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
    decision_envelope = None
    if body.decision_envelope_id is not None:
        decision_envelope = state.decision_envelopes.get(body.decision_envelope_id)
        if decision_envelope is None:
            raise HTTPException(404, f"decision envelope {body.decision_envelope_id!r} not found")
    causal_graph = None
    if body.causal_graph_id is not None:
        causal_graph = state.causal_graphs.get(body.causal_graph_id)
        if causal_graph is None:
            raise HTTPException(404, f"causal graph {body.causal_graph_id!r} not found")
    adapter = state.adapters[sealed.manifest.adapter.adapter_id]
    try:
        result = state.engine.commit(
            sealed,
            grant,
            adapter,
            context=None,
            policy_bundle=policy_bundle,
            decision_envelope=decision_envelope,
            causal_graph=causal_graph,
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


@router.post(
    "/manifests/{manifest_id}/compensation/prepare",
    dependencies=[Depends(require_auth)],
)
def prepare_compensation(manifest_id: str, request: Request) -> dict[str, Any]:
    """Build and seal a compensation manifest bound to the original effect."""
    state = _state(request)
    original = state.sealed_manifests.get(manifest_id)
    if original is None:
        raise HTTPException(404, "manifest not found")
    commit_result = state.commit_results.get(manifest_id)
    try:
        unsigned = build_compensation_manifest(original=original, original_commit=commit_result)
        state.engine.prepare_compensation(unsigned, original_sealed=original)
        sealed = state.engine.seal(unsigned, state.signing_key)
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.sealed_manifests[sealed.manifest.manifest_id] = sealed
    return {
        "compensation_manifest_id": sealed.manifest.manifest_id,
        "compensation_manifest_hash": sealed.seal.manifest_hash,
        "original_manifest_id": original.manifest.manifest_id,
        "original_manifest_hash": original.seal.manifest_hash,
        "effect_type": sealed.manifest.effect_type,
    }


@router.post(
    "/manifests/{manifest_id}/compensation/{compensation_id}/authorize",
    dependencies=[Depends(require_auth)],
)
def authorize_compensation(
    manifest_id: str,
    compensation_id: str,
    body: CompensationAuthorizeIn,
    request: Request,
) -> dict[str, Any]:
    state = _state(request)
    original = state.sealed_manifests.get(manifest_id)
    compensation = state.sealed_manifests.get(compensation_id)
    if original is None or compensation is None:
        raise HTTPException(404, "original or compensation manifest not found")
    now = datetime.now(timezone.utc)
    try:
        grant = state.engine.authorize_compensation(
            original,
            compensation,
            issuer=Principal(**body.issuer.model_dump()),
            subject=Principal(**body.subject.model_dump()),
            audience=tuple(body.audience)
            if body.audience
            else (compensation.manifest.adapter.adapter_id,),
            allowed_effect_types=(compensation.manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(seconds=body.ttl_seconds),
            signing_key=state.signing_key,
            max_uses=body.max_uses,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.register_grant(compensation_id, grant)
    return {
        "grant_id": grant.grant_id,
        "compensation_manifest_id": compensation_id,
        "original_manifest_id": manifest_id,
        "manifest_hash": grant.manifest_hash,
    }


@router.post(
    "/manifests/{manifest_id}/compensation/{compensation_id}/execute",
    dependencies=[Depends(require_auth)],
)
def execute_compensation(
    manifest_id: str,
    compensation_id: str,
    body: CompensationExecuteIn,
    request: Request,
) -> dict[str, Any]:
    state = _state(request)
    if state.kill_switch_engaged:
        raise HTTPException(503, "kill switch engaged; execution refused")
    original = state.sealed_manifests.get(manifest_id)
    compensation = state.sealed_manifests.get(compensation_id)
    grant = state.grants.get(body.grant_id)
    if original is None or compensation is None or grant is None:
        raise HTTPException(404, "manifest or grant not found")
    original_commit = state.commit_results.get(manifest_id)
    if original_commit is None:
        raise HTTPException(404, "original commit result not found; execute the original first")
    adapter = state.adapters[compensation.manifest.adapter.adapter_id]
    try:
        result = state.engine.commit_compensation(
            original,
            compensation,
            grant,
            adapter,
            context=None,
            original_commit=original_commit,
        )
    except KarmaSakshiError as exc:
        raise HTTPException(409, str(exc)) from exc
    state.commit_results[compensation_id] = result
    state.compensation_results[manifest_id] = CompensationResult(
        attempted=True,
        succeeded=result.success,
        reason=result.detail,
        detail=result.detail,
    )
    return {
        "success": result.success,
        "provider_reference": result.provider_reference,
        "detail": result.detail,
        "compensation_manifest_id": compensation_id,
        "original_manifest_id": manifest_id,
    }


@router.get(
    "/manifests/{manifest_id}/compensation/{compensation_id}/passport",
    dependencies=[Depends(require_auth)],
)
def get_compensation_passport(
    manifest_id: str, compensation_id: str, request: Request
) -> dict[str, Any]:
    state = _state(request)
    original = state.sealed_manifests.get(manifest_id)
    compensation = state.sealed_manifests.get(compensation_id)
    if original is None or compensation is None:
        raise HTTPException(404, "original or compensation manifest not found")
    grant_ids = state.grants_by_manifest.get(compensation_id, [])
    grant = state.grants[grant_ids[-1]] if grant_ids else None
    try:
        passport = build_compensation_passport(
            compensation_sealed=compensation,
            original_sealed=original,
            keyring=state.keyring,
            audit=state.engine.context.audit,
            grant=grant,
            commit_result=state.commit_results.get(compensation_id),
            outcome_proof=state.outcome_proofs.get(compensation_id),
        )
    except KarmaSakshiError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.compensation_passports[compensation_id] = passport
    return passport.model_dump(mode="json")


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


@router.get("/passports/{manifest_id}", dependencies=[Depends(require_auth)])
def get_passport(
    manifest_id: str,
    request: Request,
    fmt: str = "json",
    version: str = "v1",
) -> Any:
    """Emit an Action Passport.

    ``version=v1`` (default) returns the classic Action Passport.
    ``version=v2`` returns Action Passport V2 (schema 2.0) with
    ``passport_format``, ``outcome_status``, and ``passport_hash``.
    """
    state = _state(request)
    sealed = state.sealed_manifests.get(manifest_id)
    if sealed is None:
        raise HTTPException(404, "manifest not found")
    grant_ids = state.grants_by_manifest.get(manifest_id, [])
    grant = state.grants[grant_ids[-1]] if grant_ids else None
    lifecycle_state = state.engine.get_lifecycle_state(manifest_id).value
    ver = version.strip().lower()
    if ver in {"v2", "2", "2.0"}:
        passport_v2 = build_passport_v2(
            sealed=sealed,
            keyring=state.keyring,
            audit=state.engine.context.audit,
            lifecycle_state=lifecycle_state,
            grant=grant,
            grant_store=state.engine.context.grant_store,
            commit_result=state.commit_results.get(manifest_id),
            outcome_proof=state.outcome_proofs.get(manifest_id),
            compensation_result=state.compensation_results.get(manifest_id),
            assessment=state.assessments.get(manifest_id),
            tenant_id=state.engine.context.tenant_id,
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
        commit_result=state.commit_results.get(manifest_id),
        outcome_proof=state.outcome_proofs.get(manifest_id),
        compensation_result=state.compensation_results.get(manifest_id),
        assessment=state.assessments.get(manifest_id),
    )
    if fmt == "html":
        from fastapi.responses import HTMLResponse

        return HTMLResponse(render_passport_html(passport))
    if fmt == "markdown":
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(render_passport_markdown(passport))
    return passport.model_dump(mode="json")


@router.get("/passports/{manifest_id}/evidence-pack", dependencies=[Depends(require_auth)])
def get_evidence_pack(manifest_id: str, request: Request) -> Any:
    """Build a self-contained, offline-verifiable Evidence Pack (Phase 24):
    Action Passport V2 + sealed manifest + grant (if any) + this manifest's
    audit event slice + the public keys needed to re-verify every embedded
    signature -- with no further calls back to this API required. See
    docs/portable-evidence.md.
    """
    state = _state(request)
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
        compensation_result=state.compensation_results.get(manifest_id),
        assessment=state.assessments.get(manifest_id),
        tenant_id=state.engine.context.tenant_id,
    )
    pack = build_evidence_pack(
        passport=passport,
        sealed_manifest=sealed,
        audit=state.engine.context.audit,
        keyring=state.keyring,
        grant=grant,
    )
    return pack.model_dump(mode="json")


@router.post("/evidence-pack/verify")
def post_verify_evidence_pack(pack: dict[str, Any]) -> dict[str, Any]:
    """Independently (and fully offline) verify a submitted Evidence Pack.

    Uses only the pack's own embedded contents -- no server-side keyring,
    store, or audit journal is consulted. Deliberately unauthenticated
    (like a signature checker): a recipient with no account on this
    deployment can still verify a pack they were handed. See
    docs/portable-evidence.md.
    """
    try:
        parsed = EvidencePack.model_validate(pack)
    except (ValueError, TypeError, KarmaSakshiError) as exc:
        raise HTTPException(422, f"invalid evidence pack: {exc}") from exc
    result = verify_evidence_pack(parsed)
    return result.model_dump(mode="json")


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
