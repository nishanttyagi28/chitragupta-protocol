from __future__ import annotations

from karmasakshi.protocol.versioning import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_MAJOR_VERSIONS,
    assert_supported_schema_version,
    parse_major,
)

# NOTE: `karmasakshi.protocol.sealing` is intentionally *not* re-exported here.
# sealing.py depends on karmasakshi.domain (EffectManifest, SealedManifest),
# while karmasakshi.domain.manifest depends on karmasakshi.protocol.versioning.
# Importing sealing here would create protocol -> domain -> protocol import
# cycle at package-init time. Import `karmasakshi.protocol.sealing` directly.

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "SUPPORTED_MAJOR_VERSIONS",
    "assert_supported_schema_version",
    "parse_major",
]
