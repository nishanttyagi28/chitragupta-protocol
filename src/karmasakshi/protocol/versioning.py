"""Protocol schema versioning.

Schema versions are ``"MAJOR.MINOR"`` strings. A manifest or grant is
accepted only if its ``schema_version`` has a MAJOR component this build
understands; MINOR differences are tolerated (additive, backward-compatible
fields only). This gives explicit, testable backward/forward rejection
instead of silently accepting unknown protocol shapes.
"""

from __future__ import annotations

from karmasakshi.errors import SchemaVersionError

CURRENT_SCHEMA_VERSION = "1.0"
SUPPORTED_MAJOR_VERSIONS = frozenset({"1"})


def parse_major(schema_version: str) -> str:
    if not schema_version or "." not in schema_version:
        raise SchemaVersionError(f"malformed schema_version: {schema_version!r}")
    major, _, minor = schema_version.partition(".")
    if not major.isdigit() or not minor.isdigit():
        raise SchemaVersionError(f"malformed schema_version: {schema_version!r}")
    return major


def assert_supported_schema_version(schema_version: str) -> None:
    major = parse_major(schema_version)
    if major not in SUPPORTED_MAJOR_VERSIONS:
        raise SchemaVersionError(
            f"unsupported schema_version {schema_version!r}: "
            f"this build supports major version(s) {sorted(SUPPORTED_MAJOR_VERSIONS)}"
        )
