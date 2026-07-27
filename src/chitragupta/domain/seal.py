"""Sealing: binding a signature to a manifest's canonical hash."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from chitragupta.config.clock import ensure_utc
from chitragupta.domain.manifest import EffectManifest
from chitragupta.errors import ManifestTamperedError


class Seal(BaseModel):
    """Signature metadata binding a signer to one exact manifest hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str
    manifest_hash: str
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

    @field_validator("manifest_hash")
    @classmethod
    def _validate_manifest_hash(cls, v: str) -> str:
        if not v.startswith("sha256:") or len(v) != len("sha256:") + 64:
            raise ValueError("manifest_hash must be a sha256:<hex> digest")
        return v


class SealedManifest(BaseModel):
    """A manifest plus the seal binding a signer's identity to its hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: EffectManifest
    seal: Seal

    def verify_integrity(self) -> None:
        """Raise :class:`ManifestTamperedError` if the manifest was mutated
        after sealing (recomputed hash no longer matches the sealed hash)."""
        actual = self.manifest.canonical_hash()
        if actual != self.seal.manifest_hash:
            raise ManifestTamperedError(
                f"manifest {self.manifest.manifest_id} hash mismatch: "
                f"recomputed {actual} != sealed {self.seal.manifest_hash}"
            )


__all__ = ["Seal", "SealedManifest"]
