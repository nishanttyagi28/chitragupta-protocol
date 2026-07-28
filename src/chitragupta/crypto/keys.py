"""Ed25519 key material: generation, loading, and safe signing/verification
wrappers.

Uses ``cryptography`` (a maintained library) and Ed25519 (an established
signing primitive) -- no custom cryptography is implemented here. Private
key material is never included in ``repr()``/``str()`` output and is never
logged.
"""

from __future__ import annotations

import base64
import contextlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from chitragupta.errors import InvalidSignatureError, KeyLoadError, UnsupportedAlgorithmError

SUPPORTED_ALGORITHMS = frozenset({"ed25519"})
Algorithm = Literal["ed25519"]

_REDACTED = "<redacted-private-key-material>"


def assert_supported_algorithm(algorithm: str) -> None:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise UnsupportedAlgorithmError(
            f"unsupported signing algorithm {algorithm!r}; "
            f"supported: {sorted(SUPPORTED_ALGORITHMS)}"
        )


@dataclass(frozen=True)
class VerificationKey:
    """A public key trusted for verification, identified by ``key_id``."""

    key_id: str
    algorithm: Algorithm
    public_key: Ed25519PublicKey = field(repr=False)

    def public_bytes_b64(self) -> str:
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def verify(self, data: bytes, signature_b64: str) -> None:
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except Exception as exc:
            raise InvalidSignatureError("signature is not valid base64") from exc
        try:
            self.public_key.verify(signature, data)
        except InvalidSignature as exc:
            raise InvalidSignatureError(
                f"signature verification failed for key_id={self.key_id!r}"
            ) from exc

    @classmethod
    def from_public_bytes(
        cls, key_id: str, public_bytes: bytes, algorithm: Algorithm = "ed25519"
    ) -> VerificationKey:
        assert_supported_algorithm(algorithm)
        return cls(
            key_id=key_id,
            algorithm=algorithm,
            public_key=Ed25519PublicKey.from_public_bytes(public_bytes),
        )

    @classmethod
    def from_public_b64(
        cls, key_id: str, public_b64: str, algorithm: Algorithm = "ed25519"
    ) -> VerificationKey:
        try:
            raw = base64.b64decode(public_b64, validate=True)
        except Exception as exc:
            raise KeyLoadError("public key is not valid base64") from exc
        return cls.from_public_bytes(key_id, raw, algorithm)


@dataclass(frozen=True)
class SigningKey:
    """A private signing key. Never logged or serialized in plain repr."""

    key_id: str
    algorithm: Algorithm
    _private_key: Ed25519PrivateKey = field(repr=False)

    def __repr__(self) -> str:  # pragma: no cover - defensive redaction
        return (
            f"SigningKey(key_id={self.key_id!r}, algorithm={self.algorithm!r}, "
            f"private_key={_REDACTED})"
        )

    def sign(self, data: bytes) -> str:
        signature = self._private_key.sign(data)
        return base64.b64encode(signature).decode("ascii")

    def verification_key(self) -> VerificationKey:
        return VerificationKey(
            key_id=self.key_id,
            algorithm=self.algorithm,
            public_key=self._private_key.public_key(),
        )

    def public_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def private_bytes_for_storage(self) -> bytes:
        """Raw private key bytes, for writing to a file the caller controls.

        Callers are responsible for storing the result securely (see
        :func:`save_signing_key_to_file`). Never pass this to logging.
        """
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def generate_signing_key(key_id: str, algorithm: Algorithm = "ed25519") -> SigningKey:
    assert_supported_algorithm(algorithm)
    private_key = Ed25519PrivateKey.generate()
    return SigningKey(key_id=key_id, algorithm=algorithm, _private_key=private_key)


def save_signing_key_to_file(key: SigningKey, path: Path) -> None:
    """Write raw private key bytes to ``path`` with safe permissions where supported."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes_for_storage())
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600; best-effort on Windows ACLs


def load_signing_key_from_file(
    path: Path, key_id: str, algorithm: Algorithm = "ed25519"
) -> SigningKey:
    assert_supported_algorithm(algorithm)
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise KeyLoadError(f"could not read key file: {path}") from exc
    if len(raw) != 32:
        raise KeyLoadError("expected 32 raw Ed25519 private key bytes")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise KeyLoadError("key file did not contain a valid Ed25519 private key") from exc
    return SigningKey(key_id=key_id, algorithm=algorithm, _private_key=private_key)


def load_signing_key_from_env(
    env_var: str, key_id: str, algorithm: Algorithm = "ed25519"
) -> SigningKey:
    """Load a base64-encoded raw private key from an environment variable.

    This treats the env var as a secret-backed reference: the value itself is
    never logged, and errors never echo it back.
    """
    assert_supported_algorithm(algorithm)
    value = os.environ.get(env_var)
    if value is None:
        raise KeyLoadError(f"environment variable {env_var} is not set")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise KeyLoadError(f"environment variable {env_var} is not valid base64") from exc
    if len(raw) != 32:
        raise KeyLoadError(f"environment variable {env_var} did not decode to 32 bytes")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise KeyLoadError("decoded bytes are not a valid Ed25519 private key") from exc
    return SigningKey(key_id=key_id, algorithm=algorithm, _private_key=private_key)


__all__ = [
    "SUPPORTED_ALGORITHMS",
    "Algorithm",
    "SigningKey",
    "VerificationKey",
    "assert_supported_algorithm",
    "generate_signing_key",
    "load_signing_key_from_env",
    "load_signing_key_from_file",
    "save_signing_key_to_file",
]
