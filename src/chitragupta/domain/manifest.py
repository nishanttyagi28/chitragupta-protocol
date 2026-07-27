"""The Effect Manifest: the canonical, versioned representation of the exact
resolved real-world change an agent is proposing.

See docs/effect-manifest.md for the full field-by-field rationale and
docs/protocol-spec.md for the canonicalization/hashing algorithm.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from chitragupta.canonical.serialize import canonical_hash
from chitragupta.config.clock import ensure_utc
from chitragupta.config.settings import DEFAULT_SETTINGS, ManifestLimits, MetadataLimits
from chitragupta.domain.common import (
    AdapterIdentity,
    MonetaryAmount,
    Precondition,
    Principal,
    StateFingerprint,
)
from chitragupta.domain.enums import (
    BlastRadiusClassification,
    ReversibilityClassification,
    RiskClassification,
)
from chitragupta.protocol.versioning import (
    CURRENT_SCHEMA_VERSION,
    assert_supported_schema_version,
)

ParameterValue = str | int | bool | None


class EffectManifest(BaseModel):
    """The exact resolved effect an agent proposes to execute.

    Immutable once constructed. The canonical hash (see :meth:`canonical_hash`)
    binds every field on this model -- changing any one of them changes the
    hash, which invalidates any seal computed over the old hash (invariant #3).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    manifest_id: str
    effect_type: str
    actor: Principal
    principal: Principal
    adapter: AdapterIdentity
    target_resource: str
    parameters: dict[str, ParameterValue]
    before_state_digest: str | None = None
    expected_after_state_digest: str | None = None
    state_fingerprint: StateFingerprint | None = None
    preconditions: tuple[Precondition, ...] = ()
    risk: RiskClassification
    reversibility: ReversibilityClassification
    blast_radius: BlastRadiusClassification
    estimated_cost: MonetaryAmount | None = None
    idempotency_key: str
    created_at: datetime
    expires_at: datetime
    nonce: str
    parent_manifest_id: str | None = None
    metadata: dict[str, str] = {}

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version(cls, v: str) -> str:
        assert_supported_schema_version(v)
        return v

    @field_validator("manifest_id", "idempotency_key", "nonce")
    @classmethod
    def _validate_ids(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("identifier fields must be 1-128 chars")
        return v

    @field_validator("effect_type")
    @classmethod
    def _validate_effect_type(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("effect_type must be 1-128 chars")
        return v

    @field_validator("target_resource")
    @classmethod
    def _validate_target_resource(cls, v: str) -> str:
        limits = DEFAULT_SETTINGS.manifest_limits
        if not v or len(v) > limits.max_target_resource_length:
            raise ValueError(f"target_resource must be 1-{limits.max_target_resource_length} chars")
        return v

    @field_validator("created_at", "expires_at")
    @classmethod
    def _validate_tz_aware(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @field_validator("parameters")
    @classmethod
    def _validate_parameters(cls, v: dict[str, ParameterValue]) -> dict[str, ParameterValue]:
        limits: ManifestLimits = DEFAULT_SETTINGS.manifest_limits
        if len(v) > limits.max_parameters:
            raise ValueError(f"parameters: at most {limits.max_parameters} keys permitted")
        for key, value in v.items():
            if not key or len(key) > limits.max_parameter_key_length:
                raise ValueError(
                    f"parameter key {key!r} exceeds max length {limits.max_parameter_key_length}"
                )
            if isinstance(value, str) and len(value) > limits.max_parameter_value_length:
                raise ValueError(
                    f"parameter {key!r} value exceeds max length "
                    f"{limits.max_parameter_value_length}"
                )
        return v

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, v: dict[str, str]) -> dict[str, str]:
        limits: MetadataLimits = DEFAULT_SETTINGS.metadata_limits
        if len(v) > limits.max_keys:
            raise ValueError(f"metadata: at most {limits.max_keys} keys permitted")
        total = 0
        for key, value in v.items():
            if len(key) > limits.max_key_length:
                raise ValueError(f"metadata key {key!r} exceeds max length {limits.max_key_length}")
            if len(value) > limits.max_value_length:
                raise ValueError(
                    f"metadata value for {key!r} exceeds max length {limits.max_value_length}"
                )
            total += len(key) + len(value)
        if total > limits.max_total_bytes:
            raise ValueError(f"metadata total size exceeds {limits.max_total_bytes} bytes")
        return v

    @model_validator(mode="after")
    def _validate_time_window(self) -> EffectManifest:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be strictly after created_at")
        return self

    def canonical_hash(self) -> str:
        """The manifest's canonical hash, binding every field on this model."""
        return canonical_hash(self)

    @classmethod
    def new_id(cls) -> str:
        return str(uuid.uuid4())

    @classmethod
    def default_expiry(cls, created_at: datetime, ttl_seconds: int | None = None) -> datetime:
        default_ttl = DEFAULT_SETTINGS.manifest_limits.default_ttl_seconds
        ttl = ttl_seconds if ttl_seconds is not None else default_ttl
        return created_at + timedelta(seconds=ttl)


def new_nonce() -> str:
    return uuid.uuid4().hex


__all__ = ["EffectManifest", "ParameterValue", "new_nonce"]
