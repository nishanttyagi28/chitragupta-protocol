"""Durable organization + user models for the commercial Gateway
(Milestone A).

These are new, additive models -- they do not replace or modify anything
in the open-core protocol (`karmasakshi.domain`, `karmasakshi.tenant`).
`GatewayUser` never carries password material; credential storage and
verification live in `karmasakshi.gateway.store`, separate from this
public-facing model, the same separation of concerns already used for
`SigningKey`/`VerificationKey` (see docs/security-model.md).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.config.clock import ensure_utc

_MAX_IDENTIFIER_LEN = 256
_MAX_EMAIL_LEN = 320


class OrganizationStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class Organization(BaseModel):
    """A durable organization: the isolation boundary for the commercial
    Gateway (see docs/product/COMMERCIAL_ARCHITECTURE.md)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    org_id: str
    name: str
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    created_at: datetime

    @field_validator("org_id", "name")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or len(v) > _MAX_IDENTIFIER_LEN:
            raise ValueError(f"must be 1-{_MAX_IDENTIFIER_LEN} chars")
        return v

    @field_validator("created_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    def is_active(self) -> bool:
        return self.status == OrganizationStatus.ACTIVE


class GatewayUserRole(str, Enum):
    """Milestone A has no server-enforced RBAC yet (that is Milestone B) --
    this is metadata only, not currently checked by any authorization
    decision. See docs/limitations.md."""

    OWNER = "owner"
    MEMBER = "member"


class GatewayUser(BaseModel):
    """A team member of one organization. Never carries a password hash
    or any credential material -- see `karmasakshi.gateway.store` for
    where that lives."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: str
    org_id: str
    email: str
    display_name: str
    role: GatewayUserRole = GatewayUserRole.MEMBER
    created_at: datetime

    @field_validator("user_id", "org_id", "display_name")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or len(v) > _MAX_IDENTIFIER_LEN:
            raise ValueError(f"must be 1-{_MAX_IDENTIFIER_LEN} chars")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if not v or "@" not in v or len(v) > _MAX_EMAIL_LEN:
            raise ValueError("must be a plausible email address")
        return v

    @field_validator("created_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return ensure_utc(v)


__all__ = [
    "GatewayUser",
    "GatewayUserRole",
    "Organization",
    "OrganizationStatus",
]
