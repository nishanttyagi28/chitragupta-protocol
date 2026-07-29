"""Authenticated Control Center for the commercial refund journey.

The UI is a thin browser-facing backend-for-frontend.  Every product read
and lifecycle action is made through :class:`AsyncGatewayClient` against
the real FastAPI Gateway using an in-process ASGI transport; templates do
not reach into protocol state or manufacture outcomes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from karmasakshi.gateway.schemas import GatewayUserOut
from karmasakshi.sdk.async_client import AsyncGatewayClient
from karmasakshi.sdk.errors import KarmaSakshiApiError, KarmaSakshiSdkError

control_center_router = APIRouter(prefix="/control-center", tags=["control-center"])

_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates" / "control_center"))
_SESSION_COOKIE = "karmasakshi_cc_session"
_LOGIN_CSRF_COOKIE = "karmasakshi_cc_login_csrf"
_COOKIE_PATH = "/control-center"
_NOTICES = {
    "approval-recorded": (
        "Approval recorded. The effect remains pending until the required quorum completes."
    ),
    "authorized": "Required approval quorum completed. The exact sealed effect is authorized.",
    "denied": "Denial recorded. This sealed effect can no longer be approved.",
    "executed": "Commit attempted through the payment simulator. Review the reported outcome.",
    "verified": "Independent provider observation completed.",
    "recovered": "Ambiguous-outcome recovery re-observed provider state without a blind retry.",
}


@dataclass(frozen=True)
class _UiSession:
    token: str
    user: GatewayUserOut


def _gateway_state(request: Request) -> Any:
    return request.app.state.karmasakshi_gateway


def _is_secure(request: Request) -> bool:
    return request.url.scheme == "https"


def _apply_security_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'none'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def _render(
    request: Request,
    template: str,
    context: dict[str, Any],
    *,
    status_code: int = 200,
) -> HTMLResponse:
    response = _templates.TemplateResponse(
        request,
        template,
        context,
        status_code=status_code,
    )
    return _apply_security_headers(response)  # type: ignore[return-value]


def _redirect(location: str, *, status_code: int = 303) -> RedirectResponse:
    return _apply_security_headers(RedirectResponse(location, status_code=status_code))  # type: ignore[return-value]


def _sdk(request: Request, token: str | None = None) -> AsyncGatewayClient:
    return AsyncGatewayClient(
        "http://karmasakshi.internal",
        session_token=token,
        transport=httpx.ASGITransport(app=request.app),
    )


async def _current_session(request: Request) -> _UiSession | None:
    token = request.cookies.get(_SESSION_COOKIE)
    if not token:
        return None
    try:
        async with _sdk(request, token) as client:
            user = await client.me()
    except KarmaSakshiSdkError:
        return None
    return _UiSession(token=token, user=user)


def _csrf_token(request: Request, session_token: str) -> str:
    key: bytes = _gateway_state(request).control_center_csrf_key
    return hmac.new(key, session_token.encode("utf-8"), hashlib.sha256).hexdigest()


def _valid_csrf(request: Request, session: _UiSession, submitted: str) -> bool:
    return hmac.compare_digest(_csrf_token(request, session.token), submitted)


def _login_redirect(*, clear_session: bool = False) -> RedirectResponse:
    response = _redirect("/control-center/login")
    if clear_session:
        response.delete_cookie(_SESSION_COOKIE, path=_COOKIE_PATH)
    return response


def _friendly_api_error(exc: KarmaSakshiApiError) -> tuple[int, str]:
    if exc.status_code == 403:
        return 403, "You are not authorized for this organization or action."
    if exc.status_code == 404:
        return 404, "The requested refund was not found in your organization."
    if exc.status_code == 409:
        return 409, exc.detail[:300]
    if exc.status_code in {400, 422}:
        return 400, exc.detail[:300]
    return 502, "The Gateway could not complete this request safely."


def _error_page(
    request: Request,
    session: _UiSession,
    *,
    status_code: int,
    message: str,
) -> HTMLResponse:
    return _render(
        request,
        "error.html",
        {
            "user": session.user,
            "csrf_token": _csrf_token(request, session.token),
            "status_code": status_code,
            "message": message,
        },
        status_code=status_code,
    )


def _sdk_error_page(
    request: Request, session: _UiSession, exc: KarmaSakshiSdkError
) -> HTMLResponse:
    if isinstance(exc, KarmaSakshiApiError):
        status_code, message = _friendly_api_error(exc)
    else:
        status_code, message = 502, "The Gateway is temporarily unavailable."
    return _error_page(
        request,
        session,
        status_code=status_code,
        message=message,
    )


def _login_page(
    request: Request,
    *,
    status_code: int = 200,
    error: str | None = None,
    org_id: str = "",
    email: str = "",
) -> HTMLResponse:
    login_csrf = secrets.token_urlsafe(32)
    response = _render(
        request,
        "login.html",
        {
            "login_csrf": login_csrf,
            "error": error,
            "org_id": org_id,
            "email": email,
        },
        status_code=status_code,
    )
    response.set_cookie(
        _LOGIN_CSRF_COOKIE,
        login_csrf,
        max_age=600,
        httponly=True,
        secure=_is_secure(request),
        samesite="strict",
        path=_COOKIE_PATH,
    )
    return response


@control_center_router.get("/login")
async def login_page(request: Request) -> Response:
    if await _current_session(request) is not None:
        return _redirect("/control-center/")
    return _login_page(request)


@control_center_router.post("/login")
async def login_submit(
    request: Request,
    org_id: Annotated[str, Form()],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
) -> Response:
    login_cookie = request.cookies.get(_LOGIN_CSRF_COOKIE, "")
    if not login_cookie or not hmac.compare_digest(login_cookie, csrf_token):
        return _login_page(
            request,
            status_code=403,
            error="The login form expired. Please try again.",
            org_id=org_id,
            email=email,
        )
    try:
        async with _sdk(request) as client:
            result = await client.login(org_id=org_id, email=email, password=password)
    except KarmaSakshiSdkError:
        return _login_page(
            request,
            status_code=401,
            error="Authentication failed.",
            org_id=org_id,
            email=email,
        )

    response = _redirect("/control-center/")
    max_age = max(
        0,
        int((result.expires_at - datetime.now(timezone.utc)).total_seconds()),
    )
    response.set_cookie(
        _SESSION_COOKIE,
        result.session_token,
        max_age=max_age,
        httponly=True,
        secure=_is_secure(request),
        samesite="strict",
        path=_COOKIE_PATH,
    )
    response.delete_cookie(_LOGIN_CSRF_COOKIE, path=_COOKIE_PATH)
    return response


@control_center_router.post("/logout")
async def logout(
    request: Request,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    session = await _current_session(request)
    if session is None:
        return _login_redirect(clear_session=True)
    if not _valid_csrf(request, session, csrf_token):
        return _error_page(
            request,
            session,
            status_code=403,
            message="The security token was missing or invalid.",
        )
    try:
        async with _sdk(request, session.token) as client:
            await client.logout()
    except KarmaSakshiSdkError:
        # Clear the browser credential even if the server already expired it.
        pass
    return _login_redirect(clear_session=True)


@control_center_router.get("/")
async def dashboard(
    request: Request,
    notice: str | None = Query(default=None, max_length=32),
) -> Response:
    session = await _current_session(request)
    if session is None:
        return _login_redirect(clear_session=True)
    try:
        async with _sdk(request, session.token) as client:
            organization = await client.get_organization(session.user.org_id)
            refunds = await client.list_refunds(session.user.org_id)
            audit_events = await client.get_audit(session.user.org_id)
            audit_verified = await client.verify_audit(session.user.org_id)
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, session, exc)

    pending = [refund for refund in refunds if refund.decision_status == "pending"]
    verified = [refund for refund in refunds if refund.verification_status == "verified_match"]
    ambiguous = [refund for refund in refunds if refund.ambiguous]
    return _render(
        request,
        "dashboard.html",
        {
            "user": session.user,
            "organization": organization,
            "csrf_token": _csrf_token(request, session.token),
            "notice": _NOTICES.get(notice or ""),
            "refunds": refunds,
            "pending_count": len(pending),
            "verified_count": len(verified),
            "ambiguous_count": len(ambiguous),
            "audit_event_count": len(audit_events),
            "audit_verified": audit_verified,
        },
    )


@control_center_router.get("/approvals")
async def approvals(request: Request) -> Response:
    session = await _current_session(request)
    if session is None:
        return _login_redirect(clear_session=True)
    try:
        async with _sdk(request, session.token) as client:
            refunds = await client.list_refunds(
                session.user.org_id,
                decision_status="pending",
            )
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, session, exc)
    return _render(
        request,
        "approvals.html",
        {
            "user": session.user,
            "csrf_token": _csrf_token(request, session.token),
            "refunds": refunds,
        },
    )


@control_center_router.get("/refunds/{manifest_id}")
async def refund_detail(
    manifest_id: str,
    request: Request,
    notice: str | None = Query(default=None, max_length=32),
) -> Response:
    session = await _current_session(request)
    if session is None:
        return _login_redirect(clear_session=True)
    try:
        async with _sdk(request, session.token) as client:
            refund = await client.get_refund(session.user.org_id, manifest_id)
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, session, exc)
    return _render(
        request,
        "refund_detail.html",
        {
            "user": session.user,
            "csrf_token": _csrf_token(request, session.token),
            "refund": refund,
            "notice": _NOTICES.get(notice or ""),
        },
    )


async def _action_session(request: Request, csrf_token: str) -> _UiSession | Response:
    session = await _current_session(request)
    if session is None:
        return _login_redirect(clear_session=True)
    if not _valid_csrf(request, session, csrf_token):
        return _error_page(
            request,
            session,
            status_code=403,
            message="The security token was missing or invalid.",
        )
    return session


@control_center_router.post("/refunds/{manifest_id}/approve")
async def approve(
    manifest_id: str,
    request: Request,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    resolved = await _action_session(request, csrf_token)
    if isinstance(resolved, Response):
        return resolved
    try:
        async with _sdk(request, resolved.token) as client:
            result = await client.approve_refund(resolved.user.org_id, manifest_id)
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, resolved, exc)
    notice = "authorized" if result.authorized else "approval-recorded"
    return _redirect(f"/control-center/refunds/{manifest_id}?notice={notice}")


@control_center_router.post("/refunds/{manifest_id}/deny")
async def deny(
    manifest_id: str,
    request: Request,
    reason: Annotated[str, Form(min_length=1, max_length=200)],
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    resolved = await _action_session(request, csrf_token)
    if isinstance(resolved, Response):
        return resolved
    try:
        async with _sdk(request, resolved.token) as client:
            await client.deny_refund(resolved.user.org_id, manifest_id, reason=reason)
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, resolved, exc)
    return _redirect(f"/control-center/refunds/{manifest_id}?notice=denied")


@control_center_router.post("/refunds/{manifest_id}/execute")
async def execute(
    manifest_id: str,
    request: Request,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    resolved = await _action_session(request, csrf_token)
    if isinstance(resolved, Response):
        return resolved
    try:
        async with _sdk(request, resolved.token) as client:
            refund = await client.get_refund(resolved.user.org_id, manifest_id)
            if refund.grant_id is None:
                return _error_page(
                    request,
                    resolved,
                    status_code=409,
                    message="This refund has no server-issued execution grant.",
                )
            await client.execute_refund(
                resolved.user.org_id,
                manifest_id,
                grant_id=refund.grant_id,
            )
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, resolved, exc)
    return _redirect(f"/control-center/refunds/{manifest_id}?notice=executed")


@control_center_router.post("/refunds/{manifest_id}/verify")
async def verify(
    manifest_id: str,
    request: Request,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    resolved = await _action_session(request, csrf_token)
    if isinstance(resolved, Response):
        return resolved
    try:
        async with _sdk(request, resolved.token) as client:
            await client.verify_refund(resolved.user.org_id, manifest_id)
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, resolved, exc)
    return _redirect(f"/control-center/refunds/{manifest_id}?notice=verified")


@control_center_router.post("/refunds/{manifest_id}/recover")
async def recover(
    manifest_id: str,
    request: Request,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    resolved = await _action_session(request, csrf_token)
    if isinstance(resolved, Response):
        return resolved
    try:
        async with _sdk(request, resolved.token) as client:
            await client.recover_refund(resolved.user.org_id, manifest_id)
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, resolved, exc)
    return _redirect(f"/control-center/refunds/{manifest_id}?notice=recovered")


@control_center_router.get("/refunds/{manifest_id}/passport")
async def passport(manifest_id: str, request: Request) -> Response:
    session = await _current_session(request)
    if session is None:
        return _login_redirect(clear_session=True)
    try:
        async with _sdk(request, session.token) as client:
            passport_model = await client.get_passport(
                session.user.org_id,
                manifest_id,
                version="v2",
            )
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, session, exc)
    passport_data = passport_model.model_dump(mode="json")
    return _render(
        request,
        "passport.html",
        {
            "user": session.user,
            "csrf_token": _csrf_token(request, session.token),
            "passport": passport_model,
            "passport_json": json.dumps(passport_data, indent=2, sort_keys=True),
        },
    )


@control_center_router.get("/audit")
async def audit(
    request: Request,
    q: str | None = Query(default=None, max_length=200),
    event_type: str | None = Query(default=None, max_length=256),
    decision: str | None = Query(default=None, max_length=256),
) -> Response:
    session = await _current_session(request)
    if session is None:
        return _login_redirect(clear_session=True)
    try:
        async with _sdk(request, session.token) as client:
            events = await client.get_audit(
                session.user.org_id,
                query=q,
                event_type=event_type,
                decision=decision,
            )
            verified = await client.verify_audit(session.user.org_id)
    except KarmaSakshiSdkError as exc:
        return _sdk_error_page(request, session, exc)
    return _render(
        request,
        "audit.html",
        {
            "user": session.user,
            "csrf_token": _csrf_token(request, session.token),
            "events": list(reversed(events)),
            "verified": verified,
            "q": q or "",
            "event_type": event_type or "",
            "decision": decision or "",
        },
    )


__all__ = ["control_center_router"]
