"""API request/response schemas -- kept separate from the domain models so
the wire contract can evolve independently of internal representations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from chitragupta.domain.enums import PrincipalType


class PrincipalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    principal_type: PrincipalType
    display_name: str | None = None


class PrepareRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter: Literal["sqlite", "email", "payment"]
    actor: PrincipalIn
    principal: PrincipalIn
    idempotency_key: str = ""
    ttl_seconds: int = 300
    fields: dict[str, str | int | bool | None] = {}


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: PrincipalIn
    subject: PrincipalIn
    audience: list[str] | None = None
    max_uses: int = 1
    ttl_seconds: int = 300


class DenyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str


class ExecuteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str


class ManifestSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_id: str
    manifest_hash: str
    effect_type: str
    target_resource: str
    lifecycle_state: str
    risk: str
    reversibility: str
    created_at: datetime


__all__ = [
    "ApproveIn",
    "DenyIn",
    "ExecuteIn",
    "ManifestSummary",
    "PrepareRequestIn",
    "PrincipalIn",
]
