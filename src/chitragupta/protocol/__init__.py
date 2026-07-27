from __future__ import annotations

from chitragupta.protocol.versioning import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_MAJOR_VERSIONS,
    assert_supported_schema_version,
    parse_major,
)

# NOTE: `chitragupta.protocol.sealing` is intentionally *not* re-exported here.
# sealing.py depends on chitragupta.domain (EffectManifest, SealedManifest),
# while chitragupta.domain.manifest depends on chitragupta.protocol.versioning.
# Importing sealing here would create protocol -> domain -> protocol import
# cycle at package-init time. Import `chitragupta.protocol.sealing` directly.

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "SUPPORTED_MAJOR_VERSIONS",
    "assert_supported_schema_version",
    "parse_major",
]
