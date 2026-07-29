"""Signed, versioned policy bundles.

A ``PolicyBundle`` is the cryptographic envelope Phase 2 wraps around a
policy payload (currently only ``IntelligencePolicy.canonical_dict()``,
see ``karmasakshi.intelligence.policy.build_policy_bundle``) so that:

1. The exact policy content in force at authorization time is pinned by a
   signed hash, the same way ``Seal`` pins an ``EffectManifest``.
2. An ``ExecutionGrant`` can bind to that hash (``policy_bundle_hash``),
   so a policy edit *after* a grant was issued cannot silently change
   what was authorized -- the grant's own signature already covers the
   old hash, and ``engine.commit()`` requires the same bundle (by hash)
   to be re-presented and re-verified before the effect executes.

See docs/policy-bundles.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.canonical.serialize import canonical_hash, canonical_json_bytes
from karmasakshi.config.clock import ensure_utc
from karmasakshi.domain.common import Principal
from karmasakshi.errors import PolicyBundleTamperedError

#: Canonical JSON payload size ceiling (bytes) -- a defensive bound against
#: an oversized policy payload, consistent with the manifest/metadata size
#: limits already enforced elsewhere (config/settings.py).
MAX_PAYLOAD_BYTES = 65536


class PolicyBundle(BaseModel):
    """The unsigned policy content plus the metadata that scopes it.

    Immutable once constructed; ``canonical_hash()`` binds every field.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0"
    bundle_id: str
    bundle_version: str
    policy_type: str
    payload: dict[str, object]
    issuer: Principal
    tenant_id: str | None = None
    created_at: datetime
    effective_from: datetime
    effective_until: datetime | None = None

    @field_validator("bundle_id", "policy_type")
    @classmethod
    def _validate_ids(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("must be 1-128 chars")
        return v

    @field_validator("bundle_version")
    @classmethod
    def _validate_version(cls, v: str) -> str:
        if "." not in v or not v:
            raise ValueError("bundle_version must be a MAJOR.MINOR string")
        major, _, minor = v.partition(".")
        if not major.isdigit() or not minor.isdigit():
            raise ValueError("bundle_version must be a MAJOR.MINOR string")
        return v

    @field_validator("tenant_id")
    @classmethod
    def _validate_tenant_id(cls, v: str | None) -> str | None:
        if v is not None and (not v or len(v) > 128):
            raise ValueError("tenant_id must be 1-128 chars")
        return v

    @field_validator("created_at", "effective_from")
    @classmethod
    def _validate_tz_aware(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @field_validator("effective_until")
    @classmethod
    def _validate_effective_until(cls, v: datetime | None) -> datetime | None:
        return ensure_utc(v) if v is not None else None

    @model_validator(mode="after")
    def _validate_window(self) -> PolicyBundle:
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("effective_until must be strictly after effective_from")
        return self

    @model_validator(mode="after")
    def _validate_payload_size(self) -> PolicyBundle:
        size = len(canonical_json_bytes(self.payload))
        if size > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"policy payload exceeds {MAX_PAYLOAD_BYTES} bytes canonical (got {size})"
            )
        return self

    def canonical_hash(self) -> str:
        return canonical_hash(self)

    def is_effective_at(self, when: datetime) -> bool:
        when = ensure_utc(when)
        if when < self.effective_from:
            return False
        return not (self.effective_until is not None and when >= self.effective_until)


class PolicyBundleSeal(BaseModel):
    """Signature metadata binding a signer to one exact policy bundle hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str
    bundle_hash: str
    signature: str
    sealed_at: datetime

    @field_validator("sealed_at")
    @classmethod
    def _validate_sealed_at(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @field_validator("key_id")
    @classmethod
    def _validate_key_id(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("key_id must be 1-128 chars")
        return v

    @field_validator("bundle_hash")
    @classmethod
    def _validate_bundle_hash(cls, v: str) -> str:
        if not v.startswith("sha256:") or len(v) != len("sha256:") + 64:
            raise ValueError("bundle_hash must be a sha256:<hex> digest")
        return v


class SealedPolicyBundle(BaseModel):
    """A policy bundle plus the seal binding a signer's identity to its hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bundle: PolicyBundle
    seal: PolicyBundleSeal

    def verify_integrity(self) -> None:
        """Raise :class:`PolicyBundleTamperedError` if the bundle was
        mutated after sealing (recomputed hash no longer matches the
        sealed hash)."""
        actual = self.bundle.canonical_hash()
        if actual != self.seal.bundle_hash:
            raise PolicyBundleTamperedError(
                f"policy bundle {self.bundle.bundle_id} hash mismatch: "
                f"recomputed {actual} != sealed {self.seal.bundle_hash}"
            )


__all__ = ["MAX_PAYLOAD_BYTES", "PolicyBundle", "PolicyBundleSeal", "SealedPolicyBundle"]
