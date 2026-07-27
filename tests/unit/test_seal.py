from __future__ import annotations

from datetime import timezone

import pytest

from chitragupta.domain import SealedManifest
from chitragupta.domain.seal import Seal
from chitragupta.errors import ManifestTamperedError


def _seal_for(manifest, now, key_id="k1", signature="fake-signature-base64"):
    return Seal(
        key_id=key_id,
        manifest_hash=manifest.canonical_hash(),
        signature=signature,
        sealed_at=now.astimezone(timezone.utc),
    )


def test_sealed_manifest_verifies_when_untampered(manifest_factory, now):
    m = manifest_factory()
    sealed = SealedManifest(manifest=m, seal=_seal_for(m, now))
    sealed.verify_integrity()  # must not raise


def test_sealed_manifest_detects_tamper_via_reconstruction(manifest_factory, now):
    m = manifest_factory()
    seal = _seal_for(m, now)
    tampered = manifest_factory(target_resource="payment:beneficiary/ATTACKER")
    sealed = SealedManifest(manifest=tampered, seal=seal)
    with pytest.raises(ManifestTamperedError):
        sealed.verify_integrity()


def test_seal_rejects_malformed_manifest_hash(now):
    with pytest.raises(ValueError):
        Seal(key_id="k1", manifest_hash="not-a-real-hash", signature="sig", sealed_at=now)
