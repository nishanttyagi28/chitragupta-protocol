"""RA-001 remediation: canonical organization-id validation.

Covers the validator itself plus its two independent enforcement points --
the ``Tenant`` model boundary and the tenant control-plane storage boundary
(see `karmasakshi.tenant.org_id`, `karmasakshi.tenant.model`,
`karmasakshi.tenant.control_plane`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from karmasakshi.errors import InvalidOrganizationIdError, TenantIsolationError
from karmasakshi.tenant.control_plane import MultiTenantControlPlane
from karmasakshi.tenant.model import Tenant
from karmasakshi.tenant.org_id import (
    MAX_ORG_ID_LENGTH,
    RESERVED_WINDOWS_NAMES,
    validate_canonical_org_id,
)

VALID_IDS = ["a", "org-a", "acme", "org-1", "buyer-evaluation", "a" * MAX_ORG_ID_LENGTH]

INVALID_IDS: list[tuple[str, str]] = [
    ("", "empty"),
    ("a" * (MAX_ORG_ID_LENGTH + 1), "too long"),
    ("../escape", "posix traversal"),
    ("..\\escape", "windows traversal"),
    ("../../etc/passwd", "deep posix traversal"),
    ("/etc/passwd", "posix absolute path"),
    ("\\etc\\passwd", "backslash absolute path"),
    ("C:\\evil", "windows drive prefix"),
    ("c:/evil", "windows drive prefix lowercase"),
    ("\\\\server\\share", "UNC path"),
    ("\\\\?\\C:\\evil", "extended-length windows path"),
    ("org/../../escape", "embedded traversal"),
    ("org\x00null", "embedded NUL"),
    ("org\ttab", "control character"),
    ("org\nnewline", "control character newline"),
    ("org\x7fdel", "DEL control character"),
    ("Org-A", "uppercase"),
    ("org_a", "underscore"),
    ("org.a", "embedded dot"),
    ("-org", "leading hyphen"),
    ("org-", "trailing hyphen"),
    ("con", "reserved windows device name"),
    ("CON", "reserved windows device name uppercase would fail charset first"),
    ("nul", "reserved windows device name"),
    ("prn", "reserved windows device name"),
    ("aux", "reserved windows device name"),
    ("com1", "reserved windows device name"),
    ("lpt1", "reserved windows device name"),
    ("org\u200bzz", "zero-width space"),
    ("\uff0e\uff0e", "fullwidth dots (unicode ambiguity)"),
    ("\uff43\uff4f\uff4e", "fullwidth 'con' (unicode ambiguity)"),
    ("caf\u00e9", "non-ascii letter"),
]


@pytest.mark.parametrize("value", VALID_IDS)
def test_validate_canonical_org_id_accepts_safe_values(value: str) -> None:
    assert validate_canonical_org_id(value) == value


@pytest.mark.parametrize("value,reason", INVALID_IDS, ids=[r for _, r in INVALID_IDS])
def test_validate_canonical_org_id_rejects_unsafe_values(value: str, reason: str) -> None:
    with pytest.raises(InvalidOrganizationIdError):
        validate_canonical_org_id(value)


def test_rejected_error_messages_never_contain_a_resolved_path(tmp_path: Path) -> None:
    """Error messages must describe the abstract rule violated, never a
    filesystem path or the raw offending value, so they are safe to return
    directly to an HTTP caller."""
    for value, _ in INVALID_IDS:
        if not value:
            continue
        try:
            validate_canonical_org_id(value)
        except InvalidOrganizationIdError as exc:
            message = str(exc)
            assert str(tmp_path) not in message
            assert value not in message


def test_reserved_windows_names_are_exactly_the_documented_set() -> None:
    assert "con" in RESERVED_WINDOWS_NAMES
    assert "com9" in RESERVED_WINDOWS_NAMES
    assert "lpt9" in RESERVED_WINDOWS_NAMES
    assert "com0" not in RESERVED_WINDOWS_NAMES
    assert "constant" not in RESERVED_WINDOWS_NAMES


# --- Tenant model boundary -------------------------------------------------------


@pytest.mark.parametrize("value,_reason", INVALID_IDS, ids=[r for _, r in INVALID_IDS])
def test_tenant_model_rejects_unsafe_tenant_id(value: str, _reason: str) -> None:
    with pytest.raises(ValueError):
        Tenant(tenant_id=value, display_name="Evil Org")


def test_tenant_model_accepts_safe_tenant_id() -> None:
    t = Tenant(tenant_id="org-a", display_name="Org A")
    assert t.tenant_id == "org-a"


# --- Control-plane storage boundary ----------------------------------------------


def test_control_plane_resolved_tenant_dir_stays_under_data_root(tmp_path: Path) -> None:
    plane = MultiTenantControlPlane(data_root=tmp_path)
    plane.create_tenant(Tenant(tenant_id="org-a", display_name="A"))
    plane.get_state("org-a")
    resolved_root = tmp_path.resolve()
    expected_dir = (resolved_root / "org-a").resolve()
    assert expected_dir.is_relative_to(resolved_root)
    assert expected_dir.exists()
    assert expected_dir.is_dir()


def test_control_plane_build_state_fails_closed_on_bypassed_validation(tmp_path: Path) -> None:
    """Even if a caller reaches `_build_state` directly with a tenant_id that
    never went through `Tenant.__post_init__`, the storage boundary itself
    must independently reject it (defense in depth)."""
    plane = MultiTenantControlPlane(data_root=tmp_path)
    with pytest.raises(InvalidOrganizationIdError):
        plane._build_state("../escape")


def test_control_plane_rejects_duplicate_but_never_partially_escapes(tmp_path: Path) -> None:
    plane = MultiTenantControlPlane(data_root=tmp_path)
    plane.create_tenant(Tenant(tenant_id="org-dup", display_name="D"))
    with pytest.raises(TenantIsolationError, match="already exists"):
        plane.create_tenant(Tenant(tenant_id="org-dup", display_name="D2"))
    # No stray directories outside the configured root.
    assert {p.name for p in tmp_path.iterdir()} == {"org-dup"}
