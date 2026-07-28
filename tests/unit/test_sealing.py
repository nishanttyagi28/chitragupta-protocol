from __future__ import annotations

import pytest

from karmasakshi.crypto import Keyring
from karmasakshi.errors import InvalidSignatureError, ManifestTamperedError, UnknownKeyError
from karmasakshi.protocol.sealing import seal_manifest, verify_seal


def test_seal_and_verify_roundtrip(manifest_factory, issuer_signing_key, keyring):
    m = manifest_factory()
    sealed = seal_manifest(m, issuer_signing_key)
    verify_seal(sealed, keyring)  # must not raise


def test_verify_fails_for_untrusted_key(manifest_factory, issuer_signing_key):
    m = manifest_factory()
    sealed = seal_manifest(m, issuer_signing_key)
    empty_keyring = Keyring([])
    with pytest.raises(UnknownKeyError):
        verify_seal(sealed, empty_keyring)


def test_verify_fails_for_wrong_signer(manifest_factory, issuer_signing_key, other_signing_key):
    m = manifest_factory()
    sealed = seal_manifest(m, issuer_signing_key)
    wrong_keyring = Keyring([other_signing_key.verification_key()])
    # other_signing_key's key_id differs, so this is really an unknown-key case
    with pytest.raises(UnknownKeyError):
        verify_seal(sealed, wrong_keyring)


def test_tampering_after_seal_is_detected(manifest_factory, issuer_signing_key, keyring):
    m = manifest_factory()
    sealed = seal_manifest(m, issuer_signing_key)
    tampered_manifest = manifest_factory(target_resource="payment:beneficiary/ATTACKER")
    tampered_sealed = sealed.model_copy(update={"manifest": tampered_manifest})
    with pytest.raises(ManifestTamperedError):
        verify_seal(tampered_sealed, keyring)


def test_forged_signature_over_real_hash_fails(
    manifest_factory, issuer_signing_key, other_signing_key, keyring
):
    m = manifest_factory()
    sealed = seal_manifest(m, issuer_signing_key)
    # Attacker signs the correct hash with a different key but claims the trusted key_id.
    forged_signature = other_signing_key.sign(sealed.seal.manifest_hash.encode("utf-8"))
    forged_seal = sealed.seal.model_copy(update={"signature": forged_signature})
    forged_sealed = sealed.model_copy(update={"seal": forged_seal})
    with pytest.raises(InvalidSignatureError):
        verify_seal(forged_sealed, keyring)
