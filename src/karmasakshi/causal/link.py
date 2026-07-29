"""Signed parent-to-child links between exact manifest hashes."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.canonical.serialize import canonical_hash, canonical_json_bytes
from karmasakshi.config.clock import ensure_utc
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey


class CausalLink(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    link_id: str
    parent_manifest_hash: str
    child_manifest_hash: str
    relation: Literal["causes", "depends_on", "compensates", "verifies"] = "causes"
    created_at: datetime
    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"
    signature: str

    @field_validator("created_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("parent_manifest_hash", "child_manifest_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not value.startswith("sha256:") or len(value) != 71:
            raise ValueError("manifest hash must be sha256:<64 lowercase hex characters>")
        try:
            int(value[7:], 16)
        except ValueError as exc:
            raise ValueError("manifest hash must contain hexadecimal characters") from exc
        return value

    def signing_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})

    def canonical_hash(self) -> str:
        return canonical_hash(self)


def sign_causal_link(
    *,
    parent_manifest_hash: str,
    child_manifest_hash: str,
    relation: Literal["causes", "depends_on", "compensates", "verifies"],
    signing_key: SigningKey,
    created_at: datetime,
    link_id: str | None = None,
) -> CausalLink:
    unsigned = CausalLink(
        link_id=link_id or str(uuid.uuid4()),
        parent_manifest_hash=parent_manifest_hash,
        child_manifest_hash=child_manifest_hash,
        relation=relation,
        created_at=created_at,
        key_id=signing_key.key_id,
        signature="pending",
    )
    return unsigned.model_copy(
        update={"signature": signing_key.sign(canonical_json_bytes(unsigned.signing_payload()))}
    )


def verify_causal_link(link: CausalLink, keyring: Keyring) -> None:
    keyring.verify(
        link.key_id,
        canonical_json_bytes(link.signing_payload()),
        link.signature,
    )


__all__ = ["CausalLink", "sign_causal_link", "verify_causal_link"]
