"""The public, unauthenticated interactive demo surface.

Mounted at ``/demo`` only when ``CHITRAGUPTA_PUBLIC_DEMO=1`` is explicitly
set (see :func:`chitragupta.api.app.create_app`). This router is
intentionally isolated from the real control-plane API and console:

* it operates on its own auto-resetting :class:`~chitragupta.web.demo_state.DemoSession`,
  never on ``ApiState``;
* it only ever touches the SQLite/email/payment *simulators* -- no real
  email, no real money movement, no arbitrary SQL;
* every route here is rate-limited;
* it never signs anything with, or displays, real signing key material
  (only key IDs and public verification keys ever appear);
* the real authenticated API/console routes are unaffected and remain
  fail-closed exactly as documented in ``chitragupta.api.auth``.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from chitragupta.adapters.payment_simulator import PaymentRequest
from chitragupta.errors import ChitraguptaError
from chitragupta.grants.model import ScopeConstraints
from chitragupta.passports import build_passport, render_passport_markdown
from chitragupta.web.demo_scenarios import SCENARIO_ORDER, SCENARIO_TITLES, SCENARIOS
from chitragupta.web.demo_state import (
    AGENT,
    APPROVER,
    get_session,
    reset_session,
    session_age_seconds,
    session_ttl_seconds,
)
from chitragupta.web.rate_limit import rate_limit_dependency

REFUND_AMOUNT_MINOR_UNITS = 1_500_00  # INR 1,500.00
REFUND_BENEFICIARY = "customer-priya"

demo_router = APIRouter(
    prefix="/demo", tags=["public-demo"], dependencies=[Depends(rate_limit_dependency)]
)

_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_templates.env.globals["scenario_order"] = SCENARIO_ORDER


def _ctx(request: Request, **extra: Any) -> dict[str, Any]:
    base = {
        "request": request,
        "ttl_minutes": session_ttl_seconds() // 60,
        "age_seconds": int(session_age_seconds()),
    }
    base.update(extra)
    return base


@demo_router.get("/", response_class=HTMLResponse)
def landing(request: Request) -> HTMLResponse:
    session = get_session()
    refund = session.pending_manifests.get("__primary_refund__")
    return _templates.TemplateResponse(
        request,
        "demo/landing.html",
        _ctx(
            request,
            scenarios=SCENARIO_ORDER,
            scenario_titles=SCENARIO_TITLES,
            runs=session.scenario_runs,
            refund_pending=refund is not None,
            refund_manifest_id=refund.manifest.manifest_id if refund else None,
        ),
    )


# --- the primary guided refund flow ----------------------------------------


@demo_router.post("/refund/propose")
def propose_refund(request: Request) -> RedirectResponse:
    session = get_session()
    adapter = session.adapters["payment.simulator"]
    before_balance = session.payment_simulator.get_balance("demo-treasury")

    session.engine.propose(
        actor=AGENT,
        effect_type="payment.transfer",
        summary={"reason": "customer refund", "amount": "INR 1500.00"},
    )
    req = PaymentRequest(
        actor=AGENT,
        principal=APPROVER,
        source_account="demo-treasury",
        beneficiary=REFUND_BENEFICIARY,
        amount_minor_units=REFUND_AMOUNT_MINOR_UNITS,
        currency="INR",
        reference="refund-order-8842",
        idempotency_key=f"public-refund-{uuid.uuid4().hex[:10]}",
    )
    manifest = session.engine.prepare(adapter, req, context=None)
    sealed = session.engine.seal(manifest, session.signing_key)
    session.pending_manifests[manifest.manifest_id] = sealed
    session.pending_manifests["__primary_refund__"] = sealed
    session.commit_results[f"before:{manifest.manifest_id}"] = before_balance
    return RedirectResponse(f"/demo/refund/{manifest.manifest_id}", status_code=303)


@demo_router.get("/refund/{manifest_id}", response_class=HTMLResponse)
def refund_detail(manifest_id: str, request: Request) -> HTMLResponse:
    session = get_session()
    sealed = session.pending_manifests.get(manifest_id)
    if sealed is None:
        return _templates.TemplateResponse(
            request, "demo/not_found.html", _ctx(request, kind="manifest", key=manifest_id)
        )
    before_balance = session.commit_results.get(f"before:{manifest_id}", 0)
    after_expected = before_balance - REFUND_AMOUNT_MINOR_UNITS
    lifecycle_state = session.engine.get_lifecycle_state(manifest_id).value
    grant_ids = session.grants_by_manifest.get(manifest_id, [])
    return _templates.TemplateResponse(
        request,
        "demo/refund_detail.html",
        _ctx(
            request,
            manifest=sealed.manifest,
            seal=sealed.seal,
            lifecycle_state=lifecycle_state,
            before_balance_rupees=before_balance / 100,
            after_balance_rupees=after_expected / 100,
            grant_ids=grant_ids,
            commit_result=session.commit_results.get(manifest_id),
            outcome_proof=session.outcome_proofs.get(manifest_id),
        ),
    )


@demo_router.post("/refund/{manifest_id}/approve")
def approve_refund(manifest_id: str, request: Request) -> RedirectResponse:
    session = get_session()
    sealed = session.pending_manifests.get(manifest_id)
    if sealed is None:
        return RedirectResponse("/demo/", status_code=303)
    adapter = session.adapters["payment.simulator"]
    now = session.clock.now()
    try:
        grant = session.engine.authorize(
            sealed,
            issuer=APPROVER,
            subject=AGENT,
            audience=(adapter.adapter_id,),
            allowed_effect_types=(sealed.manifest.effect_type,),
            scope=ScopeConstraints(
                recipients=(REFUND_BENEFICIARY,),
            ),
            not_before=now,
            expires_at=now + timedelta(minutes=10),
            signing_key=session.signing_key,
        )
        session.register_grant(manifest_id, grant)
        result = session.engine.commit(sealed, grant, adapter, context=None)
        session.commit_results[manifest_id] = result
        proof = session.engine.verify(sealed.manifest, result, adapter, context=None)
        session.outcome_proofs[manifest_id] = proof
    except ChitraguptaError as exc:
        session.commit_results[manifest_id] = f"denied: {type(exc).__name__}: {exc}"
    return RedirectResponse(f"/demo/refund/{manifest_id}", status_code=303)


@demo_router.post("/refund/{manifest_id}/deny")
def deny_refund(manifest_id: str, request: Request) -> RedirectResponse:
    session = get_session()
    sealed = session.pending_manifests.get(manifest_id)
    if sealed is not None:
        session.engine.context.audit.record(
            event_type="manifest.authorization_denied",
            decision="denied",
            manifest_id=manifest_id,
            manifest_hash=sealed.seal.manifest_hash,
            actor_id=APPROVER.principal_id,
        )
    return RedirectResponse(f"/demo/refund/{manifest_id}", status_code=303)


# --- passport / audit / delegation views ------------------------------------


@demo_router.get("/passport/{manifest_id}", response_class=HTMLResponse)
def passport_view(manifest_id: str, request: Request) -> HTMLResponse:
    session = get_session()
    sealed = session.pending_manifests.get(manifest_id)
    if sealed is None:
        return _templates.TemplateResponse(
            request, "demo/not_found.html", _ctx(request, kind="passport", key=manifest_id)
        )
    grant_ids = session.grants_by_manifest.get(manifest_id, [])
    grant = session.grants[grant_ids[-1]] if grant_ids else None
    commit_result = session.commit_results.get(manifest_id)
    if not hasattr(commit_result, "success"):
        commit_result = None
    passport = build_passport(
        sealed=sealed,
        keyring=session.keyring,
        audit=session.engine.context.audit,
        lifecycle_state=session.engine.get_lifecycle_state(manifest_id).value,
        grant=grant,
        grant_store=session.engine.context.grant_store,
        commit_result=commit_result,
        outcome_proof=session.outcome_proofs.get(manifest_id),
    )
    return _templates.TemplateResponse(
        request,
        "demo/passport.html",
        _ctx(
            request, manifest_id=manifest_id, passport_markdown=render_passport_markdown(passport)
        ),
    )


@demo_router.get("/audit", response_class=HTMLResponse)
def audit_view(request: Request) -> HTMLResponse:
    session = get_session()
    events = session.engine.context.audit.all_events()
    try:
        session.engine.context.audit.verify_chain()
        audit_ok = True
    except ChitraguptaError:
        audit_ok = False
    return _templates.TemplateResponse(
        request, "demo/audit.html", _ctx(request, events=events, audit_ok=audit_ok)
    )


@demo_router.get("/delegation", response_class=HTMLResponse)
def delegation_view(request: Request) -> HTMLResponse:
    session = get_session()
    roots = [g for g in session.grants.values() if g.parent_grant_id is None]
    children_of: dict[str, list[Any]] = {}
    for g in session.grants.values():
        if g.parent_grant_id is not None:
            children_of.setdefault(g.parent_grant_id, []).append(g)
    return _templates.TemplateResponse(
        request, "demo/delegation.html", _ctx(request, roots=roots, children_of=children_of)
    )


# --- scenario runner ---------------------------------------------------------


@demo_router.post("/scenario/{key}/run")
def run_scenario(key: str, request: Request) -> RedirectResponse:
    session = get_session()
    fn = SCENARIOS.get(key)
    if fn is not None:
        run = fn(session)
        session.scenario_runs[key] = run
    return RedirectResponse(f"/demo/scenario/{key}", status_code=303)


@demo_router.get("/scenario/{key}", response_class=HTMLResponse)
def scenario_view(key: str, request: Request) -> HTMLResponse:
    session = get_session()
    if key not in SCENARIOS:
        return _templates.TemplateResponse(
            request, "demo/not_found.html", _ctx(request, kind="scenario", key=key)
        )
    run = session.scenario_runs.get(key)
    return _templates.TemplateResponse(
        request, "demo/scenario.html", _ctx(request, key=key, run=run)
    )


@demo_router.post("/reset")
def reset(request: Request) -> RedirectResponse:
    reset_session()
    return RedirectResponse("/demo/", status_code=303)


__all__ = ["demo_router"]
