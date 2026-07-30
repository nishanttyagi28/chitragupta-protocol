"""Canonical organization/tenant identifier validation (RA-001 remediation).

A ``tenant_id`` doubles as a filesystem path segment (see
`karmasakshi.tenant.control_plane.MultiTenantControlPlane._build_state`), so
its charset must be restricted to values that can never be interpreted as a
separator, an absolute path, a drive/scheme prefix, a traversal sequence, a
reserved device name, or a value whose meaning changes under Unicode
normalization. This module is the single canonical validator; every entry
point that accepts an organization id (HTTP schema, the ``Tenant`` model, and
the tenant control-plane storage boundary) must call it and must not invent a
parallel rule set.

Validation fails closed and never normalizes, truncates, or rewrites the
input -- a rejected id must never silently become a different, possibly
colliding, id.
"""

from __future__ import annotations

import unicodedata
from re import compile as _compile

from karmasakshi.errors import InvalidOrganizationIdError

#: Lowercase ASCII letters/digits, with single internal hyphens; 1-64 chars.
#: Deliberately excludes ``.`` (blocks ``..`` traversal and Windows reserved
#: "name.ext" collisions) and ``:`` (blocks drive/scheme prefixes).
_ORG_ID_RE = _compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")

#: Windows reserved device basenames (case-insensitive on Windows). Checked
#: as an exact match since the charset above already forbids the ``.``
#: extension separator that would otherwise let ``con.anything`` collide too.
RESERVED_WINDOWS_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

MAX_ORG_ID_LENGTH = 64


def validate_canonical_org_id(value: str) -> str:
    """Validate ``value`` as a canonical organization id and return it
    unchanged, or raise :class:`InvalidOrganizationIdError` (fail closed).

    Every message describes an abstract rule violation only -- never a
    resolved filesystem path -- so it is safe to return directly to a caller.
    """
    if not isinstance(value, str) or not value:
        raise InvalidOrganizationIdError("organization id must be a non-empty string")
    if len(value) > MAX_ORG_ID_LENGTH:
        raise InvalidOrganizationIdError(
            f"organization id must be {MAX_ORG_ID_LENGTH} characters or fewer"
        )
    if any(ord(ch) < 0x20 or ch == "\x7f" for ch in value):
        raise InvalidOrganizationIdError("organization id must not contain control characters")
    if unicodedata.normalize("NFKC", value) != value:
        raise InvalidOrganizationIdError(
            "organization id must already be in normalized (NFKC) ASCII form"
        )
    if "/" in value or "\\" in value:
        raise InvalidOrganizationIdError("organization id must not contain a path separator")
    if ".." in value:
        raise InvalidOrganizationIdError("organization id must not contain a traversal sequence")
    if ":" in value:
        raise InvalidOrganizationIdError(
            "organization id must not contain a drive letter or scheme prefix"
        )
    if not _ORG_ID_RE.match(value):
        raise InvalidOrganizationIdError(
            "organization id must be 1-64 lowercase ASCII letters, digits, or "
            "internal hyphens, and must not start or end with a hyphen"
        )
    if value in RESERVED_WINDOWS_NAMES:
        raise InvalidOrganizationIdError(
            "organization id collides with a reserved Windows device name"
        )
    return value


__all__ = [
    "MAX_ORG_ID_LENGTH",
    "RESERVED_WINDOWS_NAMES",
    "validate_canonical_org_id",
]
