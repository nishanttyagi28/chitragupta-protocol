"""Independent witness statements and quorum results (Phase 9)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.config.clock import ensure_utc
from karmasakshi.domain.common import Principal
from karmasakshi.protocol.versioning import CURRENT_SCHEMA_VERSION, assert_supported_schema_version


class WitnessStatement(BaseModel):
    """A signed independent observation of one effect's outcome digest.

    Distinct from approval statements (AUTHORIZE time): witnesses attest
    to what was *observed after COMMIT*, not to whether the effect may
    proceed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    statement_id: str
    manifest_hash: str
    witness_policy_hash: str
    observed_after_state_digest: str
    matched_expected: bool
    witness: Principal
    signed_at: datetime
    expires_at: datetime
    nonce: str
    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"
    signature: str | None = None

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, v: str) -> str:
        assert_supported_schema_version(v)
        return v

    @field_validator("statement_id", "nonce", "key_id")
    @classmethod
    def _ids(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("identifier fields must be 1-128 chars")
        return v

    @field_validator("manifest_hash", "witness_policy_hash")
    @classmethod
    def _hash(cls, v: str) -> str:
        if not v.startswith("sha256:") or len(v) != len("sha256:") + 64:
            raise ValueError("must be a sha256:<hex> digest")
        return v

    @field_validator("observed_after_state_digest")
    @classmethod
    def _digest(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("observed_after_state_digest must be 1-256 chars")
        return v

    @field_validator("signed_at", "expires_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @model_validator(mode="after")
    def _window(self) -> WitnessStatement:
        if self.expires_at <= self.signed_at:
            raise ValueError("expires_at must be strictly after signed_at")
        return self

    def signing_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})

    def canonical_hash(self) -> str:
        return canonical_hash(self.signing_payload())


class WitnessPolicy(BaseModel):
    """Rules for independent witness quorum at VERIFY/PROVE time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = "default-witness"
    policy_version: str = "1.0"
    required_witnesses: int = 1
    forbid_actor_as_witness: bool = True
    forbid_subject_as_witness: bool = True
    require_matched_expected: bool = True
    max_statements_considered: int = 32

    @field_validator("policy_id")
    @classmethod
    def _pid(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("policy_id must be 1-128 chars")
        return v

    @field_validator("policy_version")
    @classmethod
    def _ver(cls, v: str) -> str:
        if "." not in v:
            raise ValueError("policy_version must be a MAJOR.MINOR string")
        return v

    @field_validator("required_witnesses")
    @classmethod
    def _req(cls, v: int) -> int:
        if v < 1 or v > 16:
            raise ValueError("required_witnesses must be 1-16")
        return v

    @field_validator("max_statements_considered")
    @classmethod
    def _max(cls, v: int) -> int:
        if v < 1 or v > 128:
            raise ValueError("max_statements_considered must be 1-128")
        return v

    def canonical_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "required_witnesses": self.required_witnesses,
            "forbid_actor_as_witness": self.forbid_actor_as_witness,
            "forbid_subject_as_witness": self.forbid_subject_as_witness,
            "require_matched_expected": self.require_matched_expected,
            "max_statements_considered": self.max_statements_considered,
        }

    def policy_hash(self) -> str:
        return canonical_hash(self.canonical_dict())


DEFAULT_WITNESS_POLICY = WitnessPolicy()


class WitnessQuorumResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    satisfied: bool
    witness_policy_hash: str
    witness_set_hash: str | None = None
    accepted_witness_ids: tuple[str, ...] = ()
    rejection_reasons: tuple[str, ...] = ()


__all__ = [
    "DEFAULT_WITNESS_POLICY",
    "WitnessPolicy",
    "WitnessQuorumResult",
    "WitnessStatement",
]
