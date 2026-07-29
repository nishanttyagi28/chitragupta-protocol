"""Tests for production signer interfaces (Phase 16)."""

from __future__ import annotations

import base64

import pytest

from karmasakshi.crypto import generate_signing_key
from karmasakshi.crypto.signer import (
    EmulatedKmsSigner,
    LocalDevSigner,
    Signer,
    require_signer_env,
)
from karmasakshi.errors import KeyLoadError


def test_local_dev_signer_satisfies_protocol_and_signs():
    key = generate_signing_key("dev-1")
    signer: Signer = LocalDevSigner(key)
    assert isinstance(signer, Signer)
    sig = signer.sign(b"hello")
    signer.verification_key().verify(b"hello", sig)
    assert "LocalDevSigner" in repr(signer)
    assert key.private_bytes_for_storage() not in repr(signer).encode()


def test_emulated_kms_requires_ref_and_signs_locally():
    key = generate_signing_key("kms-1")
    with pytest.raises(KeyLoadError, match="kms_key_ref"):
        EmulatedKmsSigner(kms_key_ref="", signing_key=key)
    signer = EmulatedKmsSigner(kms_key_ref="alias/eval-only", signing_key=key)
    assert signer.kms_key_ref == "alias/eval-only"
    assert signer.provider_label == "emulated-kms"
    sig = signer.sign(b"payload")
    key.verification_key().verify(b"payload", sig)
    assert "EmulatedKmsSigner" in repr(signer)


def test_require_signer_env_fails_closed(monkeypatch):
    monkeypatch.delenv("KARMASAKSHI_SIGNER_KEY", raising=False)
    with pytest.raises(KeyLoadError):
        require_signer_env(key_id="prod-1")


def test_require_signer_env_loads(monkeypatch):
    key = generate_signing_key("env-1")
    raw = base64.b64encode(key.private_bytes_for_storage()).decode("ascii")
    monkeypatch.setenv("KARMASAKSHI_SIGNER_KEY", raw)
    loaded = require_signer_env(key_id="env-1")
    assert loaded.key_id == "env-1"
    sig = loaded.sign(b"x")
    loaded.verification_key().verify(b"x", sig)
