"""Evidence quality and provenance (extreme-v2 Phase 10).

VERIFY/PROVE must not treat an unattributed provider success claim as
conclusive independent evidence. Typed evidence records carry provenance
and freshness; evaluation fails closed on stale, unknown, or
below-threshold quality.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.config.clock import ensure_utc
from karmasakshi.protocol.versioning import CURRENT_SCHEMA_VERSION, assert_supported_schema_version


class EvidenceKind(str, Enum):
    """Ordered quality ladder (higher = stronger independent evidence)."""

    UNATTRIBUTED = "unattributed"
    PROVIDER_CLAIM = "provider_claim"
    ADAPTER_REOBSERVE = "adapter_reobserve"
    INDEPENDENT_LEDGER = "independent_ledger"
    WITNESS_ATTESTATION = "witness_attestation"


_KIND_RANK: dict[EvidenceKind, int] = {
    EvidenceKind.UNATTRIBUTED: 0,
    EvidenceKind.PROVIDER_CLAIM: 1,
    EvidenceKind.ADAPTER_REOBSERVE: 2,
    EvidenceKind.INDEPENDENT_LEDGER: 3,
    EvidenceKind.WITNESS_ATTESTATION: 4,
}


def evidence_kind_rank(kind: EvidenceKind) -> int:
    return _KIND_RANK[kind]


class EvidenceRecord(BaseModel):
    """One attributed observation of post-commit external state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    evidence_id: str
    manifest_hash: str
    kind: EvidenceKind
    source_system: str
    observation_method: str
    observed_at: datetime
    collected_at: datetime
    after_state_digest: str | None = None
    matched_expected: bool | None = None
    source_principal_id: str | None = None
    detail: str | None = None

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, v: str) -> str:
        assert_supported_schema_version(v)
        return v

    @field_validator("evidence_id", "source_system", "observation_method")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("must be 1-256 chars")
        return v

    @field_validator("manifest_hash")
    @classmethod
    def _hash(cls, v: str) -> str:
        if not v.startswith("sha256:") or len(v) != len("sha256:") + 64:
            raise ValueError("must be a sha256:<hex> digest")
        return v

    @field_validator("observed_at", "collected_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @model_validator(mode="after")
    def _order(self) -> EvidenceRecord:
        if self.collected_at < self.observed_at:
            raise ValueError("collected_at must be >= observed_at")
        return self

    def canonical_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")

    def canonical_hash(self) -> str:
        return canonical_hash(self.canonical_dict())


class EvidencePolicy(BaseModel):
    """Fail-closed rules for accepting evidence at VERIFY/PROVE time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = "default-evidence"
    policy_version: str = "1.0"
    max_age_seconds: int = 300
    min_kind: EvidenceKind = EvidenceKind.ADAPTER_REOBSERVE
    require_source_system: bool = True
    require_digest: bool = True
    reject_unattributed: bool = True
    max_records_considered: int = 32

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
            raise ValueError("policy_version must be MAJOR.MINOR")
        return v

    @field_validator("max_age_seconds")
    @classmethod
    def _age(cls, v: int) -> int:
        if v < 1 or v > 86400:
            raise ValueError("max_age_seconds must be 1-86400")
        return v

    @field_validator("max_records_considered")
    @classmethod
    def _max(cls, v: int) -> int:
        if v < 1 or v > 128:
            raise ValueError("max_records_considered must be 1-128")
        return v

    def policy_hash(self) -> str:
        return canonical_hash(
            {
                "policy_id": self.policy_id,
                "policy_version": self.policy_version,
                "max_age_seconds": self.max_age_seconds,
                "min_kind": self.min_kind.value,
                "require_source_system": self.require_source_system,
                "require_digest": self.require_digest,
                "reject_unattributed": self.reject_unattributed,
                "max_records_considered": self.max_records_considered,
            }
        )


DEFAULT_EVIDENCE_POLICY = EvidencePolicy()


class EvidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    acceptable: bool
    evidence_policy_hash: str
    evidence_set_hash: str | None = None
    accepted_evidence_ids: tuple[str, ...] = ()
    strongest_kind: EvidenceKind | None = None
    rejection_reasons: tuple[str, ...] = ()


__all__ = [
    "DEFAULT_EVIDENCE_POLICY",
    "EvidenceAssessment",
    "EvidenceKind",
    "EvidencePolicy",
    "EvidenceRecord",
    "evidence_kind_rank",
]
