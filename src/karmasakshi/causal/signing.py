"""Signing and verifying causal links -- mirrors
``approval/signing.py``: a ``CausalLink`` is itself the signed artifact,
not wrapped in a separate seal envelope. Unlike an ``ApprovalStatement``,
there is no time-window verification -- a causal link is a permanent
historical record, not a decision that can expire.
"""

from __future__ import annotations

from karmasakshi.causal.model import CausalLink, CausalRelationship
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey, assert_supported_algorithm
from karmasakshi.domain.common import Principal
from karmasakshi.errors import InvalidSignatureError
from karmasakshi.protocol.versioning import assert_supported_schema_version


def sign_causal_link(
    *,
    link_id: str,
    parent_manifest_hash: str,
    child_manifest_hash: str,
    relationship: CausalRelationship,
    recorded_by: Principal,
    signing_key: SigningKey,
    nonce: str,
    clock: Clock = SYSTEM_CLOCK,
) -> CausalLink:
    """Mint and sign a new :class:`CausalLink`.

    Unlike ``sign_approval_statement`` / ``build_policy_bundle``, there is
    no principal-type restriction on ``recorded_by`` (invariant #30 does
    not apply here): a causal link is a factual, advisory record of what
    happened, not an authorization decision -- it is never read or
    enforced by ``authorize()``/``commit()``. See
    docs/causal-effect-graphs.md.
    """
    unsigned = CausalLink(
        link_id=link_id,
        parent_manifest_hash=parent_manifest_hash,
        child_manifest_hash=child_manifest_hash,
        relationship=relationship,
        recorded_by=recorded_by,
        recorded_at=clock.now(),
        nonce=nonce,
        key_id=signing_key.key_id,
        algorithm=signing_key.algorithm,
        signature=None,
    )
    signature = signing_key.sign(unsigned.canonical_hash().encode("utf-8"))
    return unsigned.model_copy(update={"signature": signature})


def verify_causal_link_signature(link: CausalLink, keyring: Keyring) -> None:
    """Verify schema version, algorithm, and cryptographic signature only."""
    assert_supported_schema_version(link.schema_version)
    assert_supported_algorithm(link.algorithm)
    if link.signature is None:
        raise InvalidSignatureError(f"causal link {link.link_id} is unsigned")
    payload_hash = link.canonical_hash()
    keyring.verify(link.key_id, payload_hash.encode("utf-8"), link.signature)


__all__ = ["sign_causal_link", "verify_causal_link_signature"]
