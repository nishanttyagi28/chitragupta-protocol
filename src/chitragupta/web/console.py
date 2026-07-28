"""Server-rendered local web console.

No JavaScript build pipeline: plain HTML forms posting back to these
routes. Requires authentication in any non-development configuration, same
as the JSON API (see chitragupta.api.auth) -- the dev-mode banner in
base.html makes unauthenticated local mode visually unmistakable.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from chitragupta.api.auth import is_dev_mode, require_auth
from chitragupta.api.state import ApiState
from chitragupta.domain.common import Principal
from chitragupta.domain.enums import PrincipalType
from chitragupta.errors import ChitraguptaError
from chitragupta.grants.model import ScopeConstraints

console_router = APIRouter(prefix="/console", dependencies=[Depends(require_auth)])

_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _state(request: Request) -> ApiState:
    return request.app.state.chitragupta  # type: ignore[no-any-return]


def _audit_status(state: ApiState) -> bool:
    try:
        state.engine.context.audit.verify_chain()
        return True
    except ChitraguptaError:
        return False


@console_router.get("/")
def dashboard(request: Request) -> HTMLResponse:
    state = _state(request)
    all_manifests = []
    pending = []
    for mid, sealed in state.sealed_manifests.items():
        lifecycle_state = state.engine.get_lifecycle_state(mid).value
        row = {
            "manifest_id": mid,
            "effect_type": sealed.manifest.effect_type,
            "target_resource": sealed.manifest.target_resource,
            "risk": sealed.manifest.risk.value,
            "reversibility": sealed.manifest.reversibility.value,
            "lifecycle_state": lifecycle_state,
        }
        all_manifests.append(row)
        if lifecycle_state == "sealed":
            pending.append(row)
    return _templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "dev_mode": is_dev_mode(),
            "kill_switch_engaged": state.kill_switch_engaged,
            "audit_ok": _audit_status(state),
            "event_count": len(state.engine.context.audit.all_events()),
            "pending": pending,
            "all_manifests": all_manifests,
        },
    )


@console_router.get("/manifests/{manifest_id}")
def manifest_detail(manifest_id: str, request: Request) -> HTMLResponse:
    state = _state(request)
    sealed = state.sealed_manifests[manifest_id]
    return _templates.TemplateResponse(
        request,
        "manifest_detail.html",
        {
            "dev_mode": is_dev_mode(),
            "manifest": sealed.manifest,
            "seal": sealed.seal,
            "lifecycle_state": state.engine.get_lifecycle_state(manifest_id).value,
            "grant_ids": state.grants_by_manifest.get(manifest_id, []),
        },
    )


@console_router.post("/manifests/{manifest_id}/approve")
def approve(
    manifest_id: str,
    request: Request,
    issuer_id: Annotated[str, Form()],
    issuer_type: Annotated[str, Form()],
    subject_id: Annotated[str, Form()],
    max_uses: Annotated[int, Form()] = 1,
    ttl_seconds: Annotated[int, Form()] = 300,
) -> RedirectResponse:
    state = _state(request)
    sealed = state.sealed_manifests[manifest_id]
    now = datetime.now(timezone.utc)
    grant = state.engine.authorize(
        sealed,
        issuer=Principal(principal_id=issuer_id, principal_type=PrincipalType(issuer_type)),
        subject=Principal(principal_id=subject_id, principal_type=PrincipalType.AGENT),
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        signing_key=state.signing_key,
        max_uses=max_uses,
    )
    state.register_grant(manifest_id, grant)
    return RedirectResponse(f"/console/manifests/{manifest_id}", status_code=303)


@console_router.post("/manifests/{manifest_id}/deny")
def deny(
    manifest_id: str, request: Request, reason: Annotated[str, Form()] = ""
) -> RedirectResponse:
    state = _state(request)
    sealed = state.sealed_manifests[manifest_id]
    state.engine.context.audit.record(
        event_type="manifest.authorization_denied",
        decision="denied",
        manifest_id=manifest_id,
        manifest_hash=sealed.seal.manifest_hash,
        metadata={"reason": reason[:200]},
    )
    return RedirectResponse("/console/", status_code=303)


@console_router.get("/grants")
def grants_view(request: Request) -> HTMLResponse:
    state = _state(request)
    rows = []
    for g in state.grants.values():
        rows.append(
            {
                "grant_id": g.grant_id,
                "subject": g.subject.principal_id,
                "issuer": g.issuer.principal_id,
                "use_count": state.engine.context.grant_store.get_use_count(g.grant_id),
                "max_uses": g.max_uses,
                "revoked": state.engine.context.grant_store.is_revoked(g.grant_id),
                "parent_grant_id": g.parent_grant_id,
            }
        )
    return _templates.TemplateResponse(
        request, "grants.html", {"dev_mode": is_dev_mode(), "grants": rows}
    )


@console_router.post("/grants/{grant_id}/revoke")
def revoke(grant_id: str, request: Request) -> RedirectResponse:
    state = _state(request)
    grant = state.grants[grant_id]
    manifest_id = next(
        (mid for mid, ids in state.grants_by_manifest.items() if grant_id in ids), grant_id
    )
    state.engine.revoke(grant, manifest_id, revoked_by=grant.issuer)
    return RedirectResponse(request.headers.get("referer", "/console/grants"), status_code=303)


@console_router.get("/audit")
def audit_view(request: Request) -> HTMLResponse:
    state = _state(request)
    events = state.engine.context.audit.all_events()
    return _templates.TemplateResponse(
        request,
        "audit.html",
        {"dev_mode": is_dev_mode(), "audit_ok": _audit_status(state), "events": events},
    )


@console_router.post("/kill-switch/engage")
def engage(request: Request) -> RedirectResponse:
    _state(request).kill_switch_engaged = True
    return RedirectResponse("/console/", status_code=303)


@console_router.post("/kill-switch/disengage")
def disengage(request: Request) -> RedirectResponse:
    _state(request).kill_switch_engaged = False
    return RedirectResponse("/console/", status_code=303)


__all__ = ["console_router"]
