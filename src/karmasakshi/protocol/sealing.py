"""Sealing and verifying manifests: the bridge between domain models and crypto.

Signing binds a signer to a manifest's canonical hash. Verification recomputes
the hash independently and checks both hash-equality (tamper detection) and
signature validity (identity proof) -- either failing means the seal is
invalid and the effect must not execute (invariants #3, #11, #12).
"""

from __future__ import annotations

from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.domain.seal import Seal, SealedManifest


def seal_manifest(
    manifest: EffectManifest,
    signing_key: SigningKey,
    clock: Clock = SYSTEM_CLOCK,
) -> SealedManifest:
    """Sign ``manifest``'s canonical hash, producing a :class:`SealedManifest`."""
    manifest_hash = manifest.canonical_hash()
    signature = signing_key.sign(manifest_hash.encode("utf-8"))
    seal = Seal(
        algorithm=signing_key.algorithm,
        key_id=signing_key.key_id,
        manifest_hash=manifest_hash,
        signature=signature,
        sealed_at=clock.now(),
    )
    return SealedManifest(manifest=manifest, seal=seal)


def verify_seal(sealed: SealedManifest, keyring: Keyring) -> None:
    """Verify a sealed manifest end-to-end.

    Raises :class:`~karmasakshi.errors.ManifestTamperedError` if the manifest
    was mutated after sealing, :class:`~karmasakshi.errors.UnknownKeyError`
    if the seal references a key not in ``keyring``, or
    :class:`~karmasakshi.errors.InvalidSignatureError` if the signature does
    not verify against the referenced key.
    """
    sealed.verify_integrity()
    keyring.verify(
        sealed.seal.key_id, sealed.seal.manifest_hash.encode("utf-8"), sealed.seal.signature
    )


__all__ = ["seal_manifest", "verify_seal"]
