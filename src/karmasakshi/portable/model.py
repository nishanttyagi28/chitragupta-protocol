"""Portable Evidence Pack (extreme-v2 Phase 24).

A self-contained, offline-verifiable bundle: an Action Passport V2, the
audit event slice recorded for one manifest, the sealed manifest, the
execution grant (if any), and the public verification keys needed to
recheck every embedded signature. A recipient with only this one JSON
document -- no access to the original store, database, or live keyring --
can independently re-verify the seal, the grant signature, the passport's
own tamper-evident hash, and the self-consistency of the embedded audit
events (see :mod:`karmasakshi.portable.verify`).

This is not a new cryptographic primitive: every check it enables already
exists elsewhere in the protocol (:func:`karmasakshi.protocol.sealing.verify_seal`,
:func:`karmasakshi.grants.verifier.verify_grant_signature`,
:func:`karmasakshi.audit.journal.verify_event_self_consistency`). What is
new is packaging their inputs into one portable, versioned artifact. See
docs/portable-evidence.md for what this does and does not prove.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.audit.events import AuditEvent
from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.errors import SchemaVersionError
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.passports.v2 import ActionPassportV2

EVIDENCE_PACK_FORMAT: Literal["evidence_pack.v1"] = "evidence_pack.v1"
EVIDENCE_PACK_SCHEMA_VERSION = "1.0"

#: Resource ceilings for what a pack may embed (mirrors the "bounded batch"
#: pattern used by evidence/witness/approval sets elsewhere in this
#: protocol) -- enforced by the builder, not by these models directly.
MAX_EMBEDDED_AUDIT_EVENTS = 10_000
MAX_EMBEDDED_KEYS = 256


class EmbeddedVerificationKey(BaseModel):
    """A public key only -- never private material -- copied out of a
    :class:`~karmasakshi.crypto.keyring.Keyring` so a pack can be verified
    without access to the original keyring."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"
    public_key_b64: str

    @field_validator("key_id")
    @classmethod
    def _validate_key_id(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("key_id must be 1-128 chars")
        return v

    @field_validator("public_key_b64")
    @classmethod
    def _validate_public_key(cls, v: str) -> str:
        if not v:
            raise ValueError("public_key_b64 must not be empty")
        return v


class EvidencePack(BaseModel):
    """A versioned, offline-verifiable evidence bundle for one manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_format: Literal["evidence_pack.v1"] = EVIDENCE_PACK_FORMAT
    schema_version: str = EVIDENCE_PACK_SCHEMA_VERSION
    generated_at: datetime
    pack_hash: str

    manifest_id: str
    passport: ActionPassportV2
    sealed_manifest: SealedManifest
    grant: ExecutionGrant | None = None
    audit_events: tuple[AuditEvent, ...] = ()
    verification_keys: tuple[EmbeddedVerificationKey, ...] = ()

    @field_validator("schema_version")
    @classmethod
    def _validate_schema(cls, v: str) -> str:
        if v != EVIDENCE_PACK_SCHEMA_VERSION:
            raise SchemaVersionError(
                f"EvidencePack requires schema_version {EVIDENCE_PACK_SCHEMA_VERSION!r}, got {v!r}"
            )
        return v

    @field_validator("manifest_id")
    @classmethod
    def _validate_manifest_id(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("manifest_id must be 1-256 chars")
        return v

    def deterministic_payload(self) -> dict[str, object]:
        """Canonical fields excluding ``generated_at`` (per-call timestamp)
        and ``pack_hash`` itself."""
        data = self.model_dump(mode="json")
        data.pop("generated_at", None)
        data.pop("pack_hash", None)
        return data

    def compute_pack_hash(self) -> str:
        return canonical_hash(self.deterministic_payload())


__all__ = [
    "EVIDENCE_PACK_FORMAT",
    "EVIDENCE_PACK_SCHEMA_VERSION",
    "MAX_EMBEDDED_AUDIT_EVENTS",
    "MAX_EMBEDDED_KEYS",
    "EmbeddedVerificationKey",
    "EvidencePack",
]
