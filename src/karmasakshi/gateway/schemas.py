"""Request/response schemas for the Gateway HTTP API (Milestone A)."""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.gateway.models import (
    GatewayAdapterRegistration,
    GatewayAgent,
    GatewayUserRole,
    OrganizationStatus,
)
from karmasakshi.tenant.org_id import validate_canonical_org_id

#: Same charset `karmasakshi.domain.common.Principal.principal_id` requires
#: -- `user_id` doubles as the refund-journey's approving/activating
#: Principal identity (see `karmasakshi.gateway.refunds`), so it must be
#: constructible as one.
PRINCIPAL_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def validate_principal_safe_id(value: str) -> str:
    if not value or not PRINCIPAL_SAFE_ID_RE.match(value):
        raise ValueError(
            "must be 1-128 chars, start alphanumeric, and contain only [A-Za-z0-9._:-]"
        )
    return value


#: RA-009: minimum length for a *newly set* password (bootstrap owner
#: password, additional-user password). Deliberately not applied to
#: `LoginIn.password` -- login only ever checks a submitted string against
#: an existing hash, so rejecting it early would just turn a wrong-length
#: password into a confusing 422 instead of the correct 401.
MIN_PASSWORD_LENGTH = 6


def validate_new_password(value: str) -> str:
    if len(value) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if not value.strip():
        raise ValueError("password must not be entirely whitespace")
    return value


class OrganizationBootstrapIn(BaseModel):
    """Create an organization together with its first (owner) user in one
    call -- an organization cannot exist with zero users to administer
    it."""

    model_config = ConfigDict(extra="forbid")

    org_id: str
    name: str
    owner_email: str
    owner_display_name: str
    owner_password: str

    @field_validator("org_id")
    @classmethod
    def _validate_org_id(cls, v: str) -> str:
        # RA-001: org_id becomes a tenant filesystem path segment; reject
        # anything unsafe here, at the outermost HTTP boundary, before any
        # organization row or tenant directory is created.
        return validate_canonical_org_id(v)

    @field_validator("owner_password")
    @classmethod
    def _validate_owner_password(cls, v: str) -> str:
        return validate_new_password(v)


class OrganizationOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_id: str
    name: str
    status: OrganizationStatus
    created_at: datetime


class GatewayUserOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    org_id: str
    email: str
    display_name: str
    role: GatewayUserRole
    created_at: datetime


class OrganizationBootstrapOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization: OrganizationOut
    owner: GatewayUserOut


class GatewayUserCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    email: str
    display_name: str
    password: str
    role: GatewayUserRole = GatewayUserRole.MEMBER

    @field_validator("user_id")
    @classmethod
    def _validate_user_id(cls, v: str) -> str:
        return validate_principal_safe_id(v)

    @field_validator("password")
    @classmethod
    def _validate_password(cls, v: str) -> str:
        return validate_new_password(v)


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_id: str
    email: str
    password: str


class LoginOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_token: str
    expires_at: datetime
    user: GatewayUserOut


class LogoutOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    logged_out: bool


class UserListOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: list[GatewayUserOut]


class GatewayAgentRegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    display_name: str

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, v: str) -> str:
        return validate_principal_safe_id(v)


class GatewayAgentListOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agents: list[GatewayAgent]


class GatewayAdapterRegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter_id: str
    adapter_version: str


class GatewayAdapterListOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapters: list[GatewayAdapterRegistration]


__all__ = [
    "MIN_PASSWORD_LENGTH",
    "PRINCIPAL_SAFE_ID_RE",
    "GatewayAdapterListOut",
    "GatewayAdapterRegisterIn",
    "GatewayAgentListOut",
    "GatewayAgentRegisterIn",
    "GatewayUserCreateIn",
    "GatewayUserOut",
    "LoginIn",
    "LoginOut",
    "LogoutOut",
    "OrganizationBootstrapIn",
    "OrganizationBootstrapOut",
    "OrganizationOut",
    "UserListOut",
    "validate_new_password",
    "validate_principal_safe_id",
]
