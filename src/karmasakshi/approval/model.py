"""Multi-party approval domain models (extreme-v2 Phase 3).

An ``ApprovalStatement`` is a signed, expiring, single-principal
yes/no (``approve``/``dissent``) on one exact ``(manifest_hash,
approval_policy_bundle_hash)`` pair -- self-signing, structurally
identical in shape to ``ExecutionGrant`` (``signing_payload()``/
``canonical_hash()`` cover every field except ``signature``). See
docs/multi-party-authorization.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.config.clock import ensure_utc
from karmasakshi.domain.common import Principal
from karmasakshi.protocol.versioning import CURRENT_SCHEMA_VERSION, assert_supported_schema_version

Decision = Literal["approve", "dissent"]


class ApprovalStatement(BaseModel):
    """One principal's signed decision on one exact manifest, under one
    exact approval policy. Immutable once constructed; re-signing
    produces a new instance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    statement_id: str
    manifest_hash: str
    approval_policy_bundle_hash: str
    approver: Principal
    role: str | None = None
    decision: Decision
    reason: str | None = None
    signed_at: datetime
    expires_at: datetime
    nonce: str
    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"
    signature: str | None = None

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version(cls, v: str) -> str:
        assert_supported_schema_version(v)
        return v

    @field_validator("statement_id", "nonce", "key_id")
    @classmethod
    def _validate_ids(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("identifier fields must be 1-128 chars")
        return v

    @field_validator("manifest_hash", "approval_policy_bundle_hash")
    @classmethod
    def _validate_hash_fields(cls, v: str) -> str:
        if not v.startswith("sha256:") or len(v) != len("sha256:") + 64:
            raise ValueError("must be a sha256:<hex> digest")
        return v

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str | None) -> str | None:
        if v is not None and (not v or len(v) > 64):
            raise ValueError("role must be 1-64 chars")
        return v

    @field_validator("reason")
    @classmethod
    def _validate_reason(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 512:
            raise ValueError("reason must be <= 512 chars")
        return v

    @field_validator("signed_at", "expires_at")
    @classmethod
    def _validate_tz_aware(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @model_validator(mode="after")
    def _validate_time_window(self) -> ApprovalStatement:
        if self.expires_at <= self.signed_at:
            raise ValueError("expires_at must be strictly after signed_at")
        return self

    def signing_payload(self) -> dict[str, object]:
        """Everything except ``signature`` -- what actually gets signed/verified."""
        data: dict[str, object] = self.model_dump(mode="json", exclude={"signature"})
        return data

    def canonical_hash(self) -> str:
        return canonical_hash(self.signing_payload())


class QuorumResult(BaseModel):
    """The outcome of evaluating a set of ``ApprovalStatement``s against
    an ``ApprovalPolicy`` for one exact manifest. Deterministic and
    order-independent given the same statement set (see
    ``approval/quorum.py``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    satisfied: bool
    approving_count: int
    approving_principal_ids: tuple[str, ...]
    dissenting_principal_ids: tuple[str, ...]
    missing_roles: tuple[str, ...]
    rejected: tuple[tuple[str, str], ...]
    reason: str
    approval_set_hash: str


__all__ = ["ApprovalStatement", "Decision", "QuorumResult"]
