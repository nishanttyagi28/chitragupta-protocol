"""Canonical serialization and hashing.

Canonicalization algorithm (documented in full in docs/protocol-spec.md):

1. Start from a plain Python value tree containing only: ``dict``, ``list``,
   ``str``, ``int``, ``bool``, ``None``. Floats are rejected -- money and
   fingerprints must be represented as strings/ints to avoid cross-platform
   float formatting drift.
2. Dict keys are sorted lexicographically (by their raw ``str``) at every
   nesting level.
3. The tree is serialized with ``json.dumps`` using:
   - ``sort_keys=True``
   - ``separators=(",", ":")`` (no insignificant whitespace)
   - ``ensure_ascii=True`` (stable byte output independent of locale/codec)
4. The result is UTF-8 encoded to bytes.
5. The canonical hash is ``"sha256:" + hexdigest`` of those bytes.

Any two processes that canonicalize the same logical value produce identical
bytes and identical hashes -- this is what cross-process signature
verification depends on.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel

_HASH_ALGORITHM = "sha256"


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonicalized deterministically."""


def _to_plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _to_plain(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(k): _to_plain(v) for k, v in value.items()}
    if isinstance(value, (str, bool)) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalizationError(
            "floats are not permitted in canonicalized payloads; use ints (minor units) "
            "or strings for exact decimal representation"
        )
    if isinstance(value, (list, tuple, Sequence)) and not isinstance(value, (str, bytes)):
        return [_to_plain(v) for v in value]
    raise CanonicalizationError(f"cannot canonicalize value of type {type(value).__name__!r}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize ``value`` to canonical, deterministic JSON bytes."""
    plain = _to_plain(value)
    text = json.dumps(plain, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return text.encode("utf-8")


def canonical_hash(value: Any) -> str:
    """Return the canonical hash of ``value`` as ``"sha256:<hex>"``."""
    digest = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    return f"{_HASH_ALGORITHM}:{digest}"


def digest_bytes(data: bytes) -> str:
    """Return ``sha256:<hex>`` digest of raw bytes (e.g. attachment content)."""
    return f"{_HASH_ALGORITHM}:{hashlib.sha256(data).hexdigest()}"
