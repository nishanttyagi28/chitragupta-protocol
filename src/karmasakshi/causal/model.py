"""Causal effect graph domain model (extreme-v2 Phase 5).

A ``CausalLink`` is a signed, permanent record that one manifest's
effect causally relates to another's (e.g. a compensating refund
"compensates" the payment it reverses). Self-signing, structurally
identical in shape to ``ApprovalStatement`` (``signing_payload()``/
``canonical_hash()`` cover every field except ``signature``). Unlike an
``ApprovalStatement``, a causal link never expires -- it is a historical
record of what happened, not a time-bounded decision. See
docs/causal-effect-graphs.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.config.clock import ensure_utc
from karmasakshi.domain.common import Principal
from karmasakshi.protocol.versioning import CURRENT_SCHEMA_VERSION, assert_supported_schema_version

#: A closed, small set of causal relationships -- deliberately not a free
#: string, so graph consumers can reason about relationship semantics
#: deterministically rather than parsing arbitrary text.
CausalRelationship = Literal["triggers", "compensates", "depends_on", "supersedes"]


class CausalLink(BaseModel):
    """A signed edge from ``parent_manifest_hash`` to
    ``child_manifest_hash`` in a causal effect graph. Immutable once
    constructed; re-signing produces a new instance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    link_id: str
    parent_manifest_hash: str
    child_manifest_hash: str
    relationship: CausalRelationship
    recorded_by: Principal
    recorded_at: datetime
    nonce: str
    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"
    signature: str | None = None

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version(cls, v: str) -> str:
        assert_supported_schema_version(v)
        return v

    @field_validator("link_id", "nonce", "key_id")
    @classmethod
    def _validate_ids(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("identifier fields must be 1-128 chars")
        return v

    @field_validator("parent_manifest_hash", "child_manifest_hash")
    @classmethod
    def _validate_hash_fields(cls, v: str) -> str:
        if not v.startswith("sha256:") or len(v) != len("sha256:") + 64:
            raise ValueError("must be a sha256:<hex> digest")
        return v

    @field_validator("recorded_at")
    @classmethod
    def _validate_tz_aware(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @model_validator(mode="after")
    def _validate_not_self_referential(self) -> CausalLink:
        if self.parent_manifest_hash == self.child_manifest_hash:
            raise ValueError(
                f"a causal link cannot relate a manifest to itself ({self.parent_manifest_hash})"
            )
        return self

    def signing_payload(self) -> dict[str, object]:
        """Everything except ``signature`` -- what actually gets signed/verified."""
        data: dict[str, object] = self.model_dump(mode="json", exclude={"signature"})
        return data

    def canonical_hash(self) -> str:
        return canonical_hash(self.signing_payload())


__all__ = ["CausalLink", "CausalRelationship"]
