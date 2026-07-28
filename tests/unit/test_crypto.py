from __future__ import annotations

import base64

import pytest

from karmasakshi.crypto import Keyring, generate_signing_key, save_signing_key_to_file
from karmasakshi.crypto.keys import (
    load_signing_key_from_env,
    load_signing_key_from_file,
)
from karmasakshi.errors import (
    InvalidSignatureError,
    KeyLoadError,
    UnknownKeyError,
    UnsupportedAlgorithmError,
)


def test_sign_and_verify_roundtrip():
    key = generate_signing_key("k1")
    sig = key.sign(b"hello world")
    key.verification_key().verify(b"hello world", sig)


def test_tampered_message_fails_verification():
    key = generate_signing_key("k1")
    sig = key.sign(b"hello world")
    with pytest.raises(InvalidSignatureError):
        key.verification_key().verify(b"goodbye world", sig)


def test_tampered_signature_fails_verification():
    key = generate_signing_key("k1")
    sig = key.sign(b"hello world")
    raw = bytearray(base64.b64decode(sig))
    raw[0] ^= 0xFF
    tampered_sig = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(InvalidSignatureError):
        key.verification_key().verify(b"hello world", tampered_sig)


def test_malformed_base64_signature_rejected():
    key = generate_signing_key("k1")
    with pytest.raises(InvalidSignatureError):
        key.verification_key().verify(b"hello world", "not-valid-base64!!")


def test_wrong_key_fails_verification():
    key1 = generate_signing_key("k1")
    key2 = generate_signing_key("k2")
    sig = key1.sign(b"hello world")
    with pytest.raises(InvalidSignatureError):
        key2.verification_key().verify(b"hello world", sig)


def test_private_key_never_in_repr():
    key = generate_signing_key("k1")
    assert "redacted" in repr(key)
    assert repr(key).count("=") < 5  # no base64-ish private key blob leaking


def test_unsupported_algorithm_rejected():
    with pytest.raises(UnsupportedAlgorithmError):
        generate_signing_key("k1", algorithm="rsa-4096")  # type: ignore[arg-type]


def test_keyring_rotation_add_and_remove():
    key1 = generate_signing_key("k1")
    key2 = generate_signing_key("k2")
    ring = Keyring([key1.verification_key()])
    assert ring.has_key("k1")
    assert not ring.has_key("k2")

    ring.add_key(key2.verification_key())
    assert ring.has_key("k2")

    ring.remove_key("k1")
    assert not ring.has_key("k1")
    with pytest.raises(UnknownKeyError):
        ring.get("k1")


def test_keyring_unknown_key_fails_closed():
    key = generate_signing_key("k1")
    ring = Keyring([])
    with pytest.raises(UnknownKeyError):
        ring.verify("k1", b"data", key.sign(b"data"))


def test_save_and_load_signing_key_from_file(tmp_path):
    key = generate_signing_key("k1")
    path = tmp_path / "dev.key"
    save_signing_key_to_file(key, path)
    loaded = load_signing_key_from_file(path, "k1")
    sig = loaded.sign(b"round trip")
    key.verification_key().verify(b"round trip", sig)


def test_load_signing_key_from_file_rejects_bad_length(tmp_path):
    path = tmp_path / "bad.key"
    path.write_bytes(b"too-short")
    with pytest.raises(KeyLoadError):
        load_signing_key_from_file(path, "k1")


def test_load_signing_key_from_env(monkeypatch):
    key = generate_signing_key("k1")
    raw_b64 = base64.b64encode(key.private_bytes_for_storage()).decode("ascii")
    monkeypatch.setenv("KARMASAKSHI_TEST_KEY", raw_b64)
    loaded = load_signing_key_from_env("KARMASAKSHI_TEST_KEY", "k1")
    sig = loaded.sign(b"env round trip")
    key.verification_key().verify(b"env round trip", sig)


def test_load_signing_key_from_env_missing(monkeypatch):
    monkeypatch.delenv("KARMASAKSHI_TEST_KEY_MISSING", raising=False)
    with pytest.raises(KeyLoadError):
        load_signing_key_from_env("KARMASAKSHI_TEST_KEY_MISSING", "k1")


def test_load_signing_key_from_env_invalid_base64(monkeypatch):
    monkeypatch.setenv("KARMASAKSHI_TEST_KEY_BAD", "not base64 at all !!")
    with pytest.raises(KeyLoadError):
        load_signing_key_from_env("KARMASAKSHI_TEST_KEY_BAD", "k1")
