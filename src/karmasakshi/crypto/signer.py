"""Production-oriented signer interfaces (extreme-v2 Phase 16).

Honest abstractions for plugging HSM/KMS-backed signing later. This module
does **not** call AWS, GCP, Azure, or any real HSM. Emulators are local
Ed25519 only.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from karmasakshi.crypto.keys import Algorithm, SigningKey, VerificationKey


@runtime_checkable
class Signer(Protocol):
    """Anything that can produce an Ed25519 signature over bytes.

    Call sites that today accept ``SigningKey`` can accept ``Signer``
    once they only need ``key_id``, ``algorithm``, and ``sign``.
    """

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> Algorithm: ...

    def sign(self, data: bytes) -> str: ...

    def verification_key(self) -> VerificationKey: ...


class LocalDevSigner:
    """Explicitly-labelled local development signer wrapping ``SigningKey``.

    Prefer this over raw ``SigningKey`` in production-shaped wiring so it
    is obvious the material is process-local and temporary.
    """

    def __init__(self, signing_key: SigningKey, *, label: str = "local-dev") -> None:
        self._key = signing_key
        self._label = label

    @property
    def key_id(self) -> str:
        return self._key.key_id

    @property
    def algorithm(self) -> Algorithm:
        return self._key.algorithm

    @property
    def label(self) -> str:
        return self._label

    def sign(self, data: bytes) -> str:
        return self._key.sign(data)

    def verification_key(self) -> VerificationKey:
        return self._key.verification_key()

    def __repr__(self) -> str:
        return f"LocalDevSigner(key_id={self.key_id!r}, label={self._label!r})"


class EmulatedKmsSigner:
    """Local Ed25519 signer behind a fake KMS-shaped constructor.

    Accepts a ``kms_key_ref`` string for operator familiarity. Signing is
    always local Ed25519 — never network I/O, never a cloud SDK. Use for
    conformance tests and evaluation only.
    """

    def __init__(
        self,
        *,
        kms_key_ref: str,
        signing_key: SigningKey,
        provider_label: str = "emulated-kms",
    ) -> None:
        if not kms_key_ref or not kms_key_ref.strip():
            from karmasakshi.errors import KeyLoadError

            raise KeyLoadError(
                "EmulatedKmsSigner requires a non-empty kms_key_ref; "
                "refuse to invent a key identity (fail closed)"
            )
        self._ref = kms_key_ref.strip()
        self._key = signing_key
        self._provider_label = provider_label

    @property
    def key_id(self) -> str:
        return self._key.key_id

    @property
    def algorithm(self) -> Algorithm:
        return self._key.algorithm

    @property
    def kms_key_ref(self) -> str:
        return self._ref

    @property
    def provider_label(self) -> str:
        return self._provider_label

    def sign(self, data: bytes) -> str:
        return self._key.sign(data)

    def verification_key(self) -> VerificationKey:
        return self._key.verification_key()

    def __repr__(self) -> str:
        return (
            f"EmulatedKmsSigner(key_id={self.key_id!r}, "
            f"kms_key_ref={self._ref!r}, provider={self._provider_label!r})"
        )


def require_signer_env(
    env_var: str = "KARMASAKSHI_SIGNER_KEY",
    *,
    key_id: str,
) -> SigningKey:
    """Load a signing key from env or fail closed (no generated fallback).

    Production hosts must set ``env_var``; missing secrets raise
    :class:`~karmasakshi.errors.KeyLoadError` rather than inventing a key.
    """
    from karmasakshi.crypto.keys import load_signing_key_from_env

    return load_signing_key_from_env(env_var, key_id=key_id)


__all__ = [
    "EmulatedKmsSigner",
    "LocalDevSigner",
    "Signer",
    "require_signer_env",
]
