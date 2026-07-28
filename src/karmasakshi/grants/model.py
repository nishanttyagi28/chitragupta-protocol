"""The Execution Grant: a signed, scoped, expiring, revocable, consumable
authorization to execute exactly one sealed manifest (or, for delegation
"capability" grants, to request a narrower child grant later).

See docs/execution-grants.md for the full rationale.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.config.clock import ensure_utc
from karmasakshi.domain.common import MonetaryAmount, Principal
from karmasakshi.protocol.versioning import CURRENT_SCHEMA_VERSION, assert_supported_schema_version


def _dedupe_sorted(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


class ScopeConstraints(BaseModel):
    """The narrowable dimensions of authority carried by a grant.

    ``None`` means "unrestricted along this dimension" and may only appear
    on root/policy-issued grants -- any child grant that narrows a parent
    must replace ``None`` with an explicit, narrower value or inherit the
    parent's explicit value; a child may never turn an explicit parent
    constraint back into ``None`` (that would be widening).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_resources: tuple[str, ...] | None = None
    recipients: tuple[str, ...] | None = None
    max_amount: MonetaryAmount | None = None
    allowed_fields: tuple[str, ...] | None = None
    environments: tuple[str, ...] | None = None

    @field_validator("target_resources", "recipients", "allowed_fields", "environments")
    @classmethod
    def _normalize_tuples(cls, v: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if v is None:
            return None
        if len(v) == 0:
            raise ValueError(
                "an explicit empty allow-list forbids everything; use null for unrestricted"
            )
        return _dedupe_sorted(v)


class ExecutionGrant(BaseModel):
    """A signed authorization. Frozen; re-signing produces a new instance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    grant_id: str
    manifest_hash: str | None = None
    issuer: Principal
    subject: Principal
    audience: tuple[str, ...]
    allowed_effect_types: tuple[str, ...]
    scope: ScopeConstraints
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    max_uses: int = 1
    nonce: str
    parent_grant_id: str | None = None
    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"
    signature: str | None = None

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version(cls, v: str) -> str:
        assert_supported_schema_version(v)
        return v

    @field_validator("grant_id", "nonce", "key_id")
    @classmethod
    def _validate_ids(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("identifier fields must be 1-128 chars")
        return v

    @field_validator("manifest_hash")
    @classmethod
    def _validate_manifest_hash(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not v.startswith("sha256:") or len(v) != len("sha256:") + 64:
            raise ValueError("manifest_hash must be a sha256:<hex> digest")
        return v

    @field_validator("audience", "allowed_effect_types")
    @classmethod
    def _validate_nonempty_tuples(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if len(v) == 0:
            raise ValueError("must contain at least one value")
        return _dedupe_sorted(v)

    @field_validator("max_uses")
    @classmethod
    def _validate_max_uses(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_uses must be >= 1")
        return v

    @field_validator("issued_at", "not_before", "expires_at")
    @classmethod
    def _validate_tz_aware(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @model_validator(mode="after")
    def _validate_time_window(self) -> ExecutionGrant:
        if self.expires_at <= self.not_before:
            raise ValueError("expires_at must be strictly after not_before")
        return self

    def signing_payload(self) -> dict[str, object]:
        """Everything except ``signature`` -- what actually gets signed/verified."""
        data: dict[str, object] = self.model_dump(mode="json", exclude={"signature"})
        return data

    def canonical_hash(self) -> str:
        return canonical_hash(self.signing_payload())

    def is_manifest_bound(self) -> bool:
        return self.manifest_hash is not None


__all__ = ["ExecutionGrant", "ScopeConstraints"]
