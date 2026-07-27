"""Keyring: multiple trusted verification keys with rotation support.

Separation of concerns: a :class:`SigningKey` can sign; a
:class:`~chitragupta.crypto.keys.VerificationKey` can only verify. Callers
that need to verify signatures (the engine, CLI, API) should only ever hold
a :class:`Keyring`, never a private key.
"""

from __future__ import annotations

from chitragupta.crypto.keys import VerificationKey
from chitragupta.errors import UnknownKeyError


class Keyring:
    """A set of trusted verification keys, indexed by key_id.

    Supports rotation: adding a new key does not invalidate old ones, and
    revoking (removing) a key immediately makes any signature referencing it
    fail closed with :class:`UnknownKeyError`.
    """

    def __init__(self, keys: list[VerificationKey] | None = None) -> None:
        self._keys: dict[str, VerificationKey] = {}
        for k in keys or []:
            self.add_key(k)

    def add_key(self, key: VerificationKey) -> None:
        self._keys[key.key_id] = key

    def remove_key(self, key_id: str) -> None:
        self._keys.pop(key_id, None)

    def has_key(self, key_id: str) -> bool:
        return key_id in self._keys

    def get(self, key_id: str) -> VerificationKey:
        key = self._keys.get(key_id)
        if key is None:
            raise UnknownKeyError(f"unknown or revoked key_id: {key_id!r}")
        return key

    def verify(self, key_id: str, data: bytes, signature_b64: str) -> None:
        key = self.get(key_id)
        key.verify(data, signature_b64)

    def key_ids(self) -> list[str]:
        return sorted(self._keys.keys())


__all__ = ["Keyring"]
