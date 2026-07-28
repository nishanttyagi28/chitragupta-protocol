"""The structured output of the Effect Intelligence Engine.

``EffectAssessment`` is deliberately not free text: every field is a
named, typed fact or a value computed from named, typed facts. The
``explanation`` field is a deterministic rendering of those facts, never
an LLM-generated narrative (operating rule #8: LLMs may explain, never
decide -- and here nothing decides at all except versioned policy
arithmetic).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.config.clock import ensure_utc


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Recommendation(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class VerificationStrength(str, Enum):
    STANDARD = "standard"
    STRONG = "strong"
    INDEPENDENT = "independent"


class RiskSignal(BaseModel):
    """One named, weighted fact that contributed to (or would have forced)
    the assessment's recommendation. ``weight == 0`` signals are either
    informational (e.g. a favorable classification) or a forced-block
    reason recorded for audit purposes -- see ``EffectAssessment.explanation``
    for which is which."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    weight: int
    detail: str

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("signal name must be 1-128 chars")
        return v

    @field_validator("weight")
    @classmethod
    def _validate_weight(cls, v: int) -> int:
        if v < 0 or v > 100:
            raise ValueError("signal weight must be 0-100")
        return v

    @field_validator("detail")
    @classmethod
    def _validate_detail(cls, v: str) -> str:
        if len(v) > 512:
            raise ValueError("signal detail must be <= 512 chars")
        return v


class EffectAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment_id: str
    manifest_id: str
    manifest_hash: str
    policy_id: str
    policy_version: str
    policy_hash: str
    score: int
    risk_level: RiskLevel
    signals: tuple[RiskSignal, ...]
    recommendation: Recommendation
    required_human_approvals: int
    required_service_approvals: int
    cooling_off_period_seconds: int
    required_witness_quorum: int
    required_verification_strength: VerificationStrength
    explanation: str
    assessed_at: datetime

    @field_validator("assessed_at")
    @classmethod
    def _validate_assessed_at(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @field_validator("score")
    @classmethod
    def _validate_score(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError("score must be 0-100")
        return v

    @field_validator(
        "assessment_id",
        "manifest_id",
        "manifest_hash",
        "policy_id",
        "policy_version",
        "policy_hash",
    )
    @classmethod
    def _validate_nonempty(cls, v: str) -> str:
        if not v or len(v) > 512:
            raise ValueError("must be 1-512 chars")
        return v

    @field_validator(
        "required_human_approvals",
        "required_service_approvals",
        "cooling_off_period_seconds",
        "required_witness_quorum",
    )
    @classmethod
    def _validate_nonnegative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("must be >= 0")
        return v

    def deterministic_payload(self) -> dict[str, object]:
        """Everything about this assessment that must be reproducible given
        the same manifest + policy + facts -- excludes ``assessment_id`` and
        ``assessed_at``, which are per-call identifiers, not scoring
        outputs. Two assessments of the same inputs, run in two different
        processes, always produce the same :meth:`deterministic_hash`."""
        return {
            "manifest_id": self.manifest_id,
            "manifest_hash": self.manifest_hash,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "score": self.score,
            "risk_level": self.risk_level.value,
            "signals": [
                {"name": s.name, "weight": s.weight, "detail": s.detail} for s in self.signals
            ],
            "recommendation": self.recommendation.value,
            "required_human_approvals": self.required_human_approvals,
            "required_service_approvals": self.required_service_approvals,
            "cooling_off_period_seconds": self.cooling_off_period_seconds,
            "required_witness_quorum": self.required_witness_quorum,
            "required_verification_strength": self.required_verification_strength.value,
            "explanation": self.explanation,
        }

    def deterministic_hash(self) -> str:
        return canonical_hash(self.deterministic_payload())


__all__ = [
    "EffectAssessment",
    "Recommendation",
    "RiskLevel",
    "RiskSignal",
    "VerificationStrength",
]
