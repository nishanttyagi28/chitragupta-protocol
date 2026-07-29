"""Request/response schemas for the Gateway HTTP API (Milestone A)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from karmasakshi.gateway.models import GatewayUserRole, OrganizationStatus


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


class UserListOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: list[GatewayUserOut]


__all__ = [
    "GatewayUserCreateIn",
    "GatewayUserOut",
    "LoginIn",
    "LoginOut",
    "OrganizationBootstrapIn",
    "OrganizationBootstrapOut",
    "OrganizationOut",
    "UserListOut",
]
