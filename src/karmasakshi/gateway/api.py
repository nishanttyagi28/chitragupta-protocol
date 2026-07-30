"""Gateway HTTP API (Milestone A): organization bootstrap, login, and
org-scoped user management.

Mounted under ``/gateway`` alongside the existing protocol control-plane
API (see `karmasakshi.api.app.create_app`). Organization *creation* is a
platform-operator action gated by the same `karmasakshi.api.auth.require_auth`
dev-mode/token check as the rest of the control plane; everything else
here is gated by a Gateway session issued at login, scoped to one
organization. See docs/gateway.md.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from karmasakshi.api.auth import require_auth
from karmasakshi.api.state import ApiState
from karmasakshi.errors import (
    CrossOrganizationAccessError,
    GatewayAdapterAlreadyExistsError,
    GatewayAdapterNotFoundError,
    GatewayAgentAlreadyExistsError,
    GatewayAgentNotFoundError,
    GatewayAuthenticationError,
    GatewayUserAlreadyExistsError,
    InvalidOrganizationIdError,
    KarmaSakshiError,
    OrganizationAlreadyExistsError,
    OrganizationNotFoundError,
    OrganizationSuspendedError,
    TenantIsolationError,
    UntrustedAdapterError,
)
from karmasakshi.gateway.models import (
    GatewayAdapterRegistration,
    GatewayAgent,
    GatewayUser,
    GatewayUserRole,
    Organization,
)
from karmasakshi.gateway.schemas import (
    GatewayAdapterListOut,
    GatewayAdapterRegisterIn,
    GatewayAgentListOut,
    GatewayAgentRegisterIn,
    GatewayUserCreateIn,
    GatewayUserOut,
    LoginIn,
    LoginOut,
    LogoutOut,
    OrganizationBootstrapIn,
    OrganizationBootstrapOut,
    OrganizationOut,
    UserListOut,
)
from karmasakshi.gateway.sessions import GatewaySessionStore
from karmasakshi.gateway.store import GatewayStore
from karmasakshi.tenant.control_plane import MultiTenantControlPlane
from karmasakshi.tenant.model import Tenant
from karmasakshi.tenant.org_id import validate_canonical_org_id

router = APIRouter(prefix="/gateway", tags=["gateway"])


@dataclass
class GatewayApiState:
    store: GatewayStore
    sessions: GatewaySessionStore = field(default_factory=GatewaySessionStore)
    control_center_csrf_key: bytes = field(
        default_factory=lambda: secrets.token_bytes(32), repr=False
    )
    #: Gives each organization its own isolated protocol engine, adapters,
    #: grant store, and audit journal (reuses Phase 19's multi-tenant
    #: control plane -- karmasakshi.gateway.Organization and
    #: karmasakshi.tenant.Tenant are separate models sharing the same
    #: org_id/tenant_id string; see docs/gateway.md).
    control_plane: MultiTenantControlPlane = field(default_factory=MultiTenantControlPlane)


def _state(request: Request) -> GatewayApiState:
    return request.app.state.karmasakshi_gateway  # type: ignore[no-any-return]


def _user_out(user: GatewayUser) -> GatewayUserOut:
    return GatewayUserOut(
        user_id=user.user_id,
        org_id=user.org_id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        created_at=user.created_at,
    )


def _organization_out(org: Organization) -> OrganizationOut:
    return OrganizationOut(
        org_id=org.org_id,
        name=org.name,
        status=org.status,
        created_at=org.created_at,
    )


async def require_gateway_session(
    request: Request,
    authorization: str | None = Header(default=None),
) -> GatewayUser:
    """FastAPI dependency: resolve the bearer session token to its
    authenticated `GatewayUser`, failing closed (401) on any of: missing
    header, malformed header, unknown token, or expired token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing or malformed Authorization header")
    token = authorization.removeprefix("Bearer ")
    state = _state(request)
    session = state.sessions.get(token)
    if session is None:
        raise HTTPException(401, "invalid or expired session")
    try:
        return state.store.get_user_by_id(session.org_id, session.user_id)
    except KarmaSakshiError as exc:
        raise HTTPException(401, "session no longer valid") from exc


def _assert_org_scope(request: Request, user: GatewayUser, org_id: str) -> None:
    # RA-001: every org-scoped route (including path-param routes that never
    # go through `OrganizationBootstrapIn`) funnels through here, so reject a
    # malformed org_id before any store lookup or control-plane access.
    try:
        validate_canonical_org_id(org_id)
    except InvalidOrganizationIdError as exc:
        raise HTTPException(400, str(exc)) from exc
    state = _state(request)
    try:
        state.store.assert_user_belongs_to_organization(user, org_id)
        state.store.require_active_organization(org_id)
    except CrossOrganizationAccessError as exc:
        raise HTTPException(403, str(exc)) from exc
    except OrganizationSuspendedError as exc:
        raise HTTPException(403, str(exc)) from exc
    except OrganizationNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc


def resolve_org_runtime(request: Request, user: GatewayUser, org_id: str) -> ApiState:
    """Verify ``user``'s session actually belongs to ``org_id`` (fails
    closed, 403, otherwise), then return that organization's isolated
    protocol engine/adapters/audit state. The single entry point every
    org-scoped, non-Gateway-model endpoint (e.g. the refund journey in
    `karmasakshi.gateway.refunds`) should use."""
    _assert_org_scope(request, user, org_id)
    state = _state(request)
    try:
        return state.control_plane.get_state(org_id)
    except TenantIsolationError as exc:
        raise HTTPException(404, str(exc)) from exc


def require_registered_refund_resources(
    request: Request,
    user: GatewayUser,
    org_id: str,
    *,
    agent_id: str,
    adapter_id: str,
    adapter_version: str,
) -> ApiState:
    """Resolve an org runtime only when the proposal's agent and concrete
    adapter version are present in that organization's durable inventory."""
    runtime = resolve_org_runtime(request, user, org_id)
    store = _state(request).store
    try:
        store.get_agent(org_id, agent_id)
    except GatewayAgentNotFoundError as exc:
        raise HTTPException(409, f"refund agent {agent_id!r} is not registered") from exc
    try:
        registration = store.get_adapter(org_id, adapter_id)
    except GatewayAdapterNotFoundError as exc:
        raise HTTPException(409, f"adapter {adapter_id!r} is not registered") from exc
    if registration.adapter_version != adapter_version:
        raise HTTPException(409, "registered adapter version does not match the runtime")
    if "payment.transfer" not in registration.effect_types:
        raise HTTPException(409, "registered adapter does not allow payment.transfer")
    return runtime


@router.post("/organizations", dependencies=[Depends(require_auth)])
def bootstrap_organization(
    body: OrganizationBootstrapIn, request: Request
) -> OrganizationBootstrapOut:
    """Create a new organization together with its first (owner) user, and
    provision its isolated protocol engine/adapters/audit state (Phase 19
    multi-tenant control plane). Platform-operator action -- gated by the
    control plane's own dev-mode/token auth, not a Gateway session (there
    is no user yet)."""
    state = _state(request)
    try:
        org = state.store.create_organization(body.org_id, body.name)
        owner = state.store.create_user(
            user_id=f"{body.org_id}-owner",
            org_id=body.org_id,
            email=body.owner_email,
            display_name=body.owner_display_name,
            password=body.owner_password,
            role=GatewayUserRole.OWNER,
        )
    except OrganizationAlreadyExistsError as exc:
        raise HTTPException(409, str(exc)) from exc
    except GatewayUserAlreadyExistsError as exc:
        raise HTTPException(409, str(exc)) from exc
    try:
        state.control_plane.create_tenant(
            Tenant(tenant_id=body.org_id, display_name=body.name, created_at=org.created_at)
        )
    except InvalidOrganizationIdError as exc:
        # Defense in depth: `OrganizationBootstrapIn.org_id` already rejects
        # this at the schema boundary, so this should be unreachable in
        # practice, but this call site must not trust that upstream check.
        raise HTTPException(400, str(exc)) from exc
    except TenantIsolationError as exc:
        raise HTTPException(409, str(exc)) from exc
    return OrganizationBootstrapOut(
        organization=_organization_out(org),
        owner=_user_out(owner),
    )


@router.post("/auth/login")
def login(body: LoginIn, request: Request) -> LoginOut:
    """Authenticate a user against one organization and issue a session
    token. Deliberately public (no platform auth) -- this *is* the
    authentication step."""
    state = _state(request)
    try:
        user = state.store.authenticate(
            org_id=body.org_id, email=body.email, password=body.password
        )
    except GatewayAuthenticationError as exc:
        raise HTTPException(401, "authentication failed") from exc
    session = state.sessions.issue(user)
    return LoginOut(
        session_token=session.token,
        expires_at=session.expires_at,
        user=_user_out(user),
    )


@router.get("/auth/me")
def me(user: Annotated[GatewayUser, Depends(require_gateway_session)]) -> GatewayUserOut:
    return _user_out(user)


@router.post("/auth/logout")
def logout(
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
    authorization: str = Header(),
) -> LogoutOut:
    """Revoke exactly the authenticated bearer session.

    ``user`` is intentionally retained as a dependency even though the
    response does not need it: an unknown or expired token must not be
    reported as a successful logout.
    """
    del user
    _state(request).sessions.revoke(authorization.removeprefix("Bearer "))
    return LogoutOut(logged_out=True)


@router.get("/organizations/{org_id}")
def get_organization(
    org_id: str, request: Request, user: Annotated[GatewayUser, Depends(require_gateway_session)]
) -> OrganizationOut:
    _assert_org_scope(request, user, org_id)
    state = _state(request)
    try:
        org = state.store.get_organization(org_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    return _organization_out(org)


@router.get("/organizations/{org_id}/users")
def list_organization_users(
    org_id: str, request: Request, user: Annotated[GatewayUser, Depends(require_gateway_session)]
) -> UserListOut:
    _assert_org_scope(request, user, org_id)
    state = _state(request)
    try:
        users = state.store.list_users(org_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except OrganizationSuspendedError as exc:
        raise HTTPException(403, str(exc)) from exc
    return UserListOut(users=[_user_out(u) for u in users])


@router.post("/organizations/{org_id}/users")
def create_organization_user(
    org_id: str,
    body: GatewayUserCreateIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> GatewayUserOut:
    _assert_org_scope(request, user, org_id)
    state = _state(request)
    try:
        created = state.store.create_user(
            user_id=body.user_id,
            org_id=org_id,
            email=body.email,
            display_name=body.display_name,
            password=body.password,
            role=body.role,
        )
    except GatewayUserAlreadyExistsError as exc:
        raise HTTPException(409, str(exc)) from exc
    except OrganizationSuspendedError as exc:
        raise HTTPException(403, str(exc)) from exc
    return _user_out(created)


@router.post("/organizations/{org_id}/agents")
def register_organization_agent(
    org_id: str,
    body: GatewayAgentRegisterIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> GatewayAgent:
    _assert_org_scope(request, user, org_id)
    try:
        return _state(request).store.register_agent(
            org_id=org_id,
            agent_id=body.agent_id,
            display_name=body.display_name,
        )
    except GatewayAgentAlreadyExistsError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/organizations/{org_id}/agents")
def list_organization_agents(
    org_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> GatewayAgentListOut:
    _assert_org_scope(request, user, org_id)
    return GatewayAgentListOut(agents=_state(request).store.list_agents(org_id))


@router.post("/organizations/{org_id}/adapters")
def register_organization_adapter(
    org_id: str,
    body: GatewayAdapterRegisterIn,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> GatewayAdapterRegistration:
    runtime = resolve_org_runtime(request, user, org_id)
    adapter = runtime.adapters.get(body.adapter_id)
    if adapter is None:
        raise HTTPException(404, "adapter is not available in this Gateway runtime")
    if adapter.adapter_version != body.adapter_version:
        raise HTTPException(409, "adapter version does not match the running adapter")
    try:
        capability = runtime.adapter_registry.require(body.adapter_id, body.adapter_version)
        return _state(request).store.register_adapter(
            org_id=org_id,
            adapter_id=body.adapter_id,
            adapter_version=body.adapter_version,
            effect_types=capability.supported_effect_types,
        )
    except UntrustedAdapterError as exc:
        raise HTTPException(403, str(exc)) from exc
    except GatewayAdapterAlreadyExistsError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/organizations/{org_id}/adapters")
def list_organization_adapters(
    org_id: str,
    request: Request,
    user: Annotated[GatewayUser, Depends(require_gateway_session)],
) -> GatewayAdapterListOut:
    _assert_org_scope(request, user, org_id)
    return GatewayAdapterListOut(adapters=_state(request).store.list_adapters(org_id))


__all__ = [
    "GatewayApiState",
    "require_gateway_session",
    "require_registered_refund_resources",
    "resolve_org_runtime",
    "router",
]
