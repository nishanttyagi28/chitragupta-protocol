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
    "validate_principal_safe_id",
]
