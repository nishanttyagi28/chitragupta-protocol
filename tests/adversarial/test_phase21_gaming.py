"""Phase 21 adversarial gaming of tenant isolation and resource protection."""

from __future__ import annotations

import pytest

from karmasakshi.errors import RequestTooLargeError, TenantIsolationError
from karmasakshi.protection.limits import enforce_content_length
from karmasakshi.tenant.enforce import assert_tenant_match


def test_cannot_bypass_tenant_match_with_whitespace_lookalikes() -> None:
    # assert_tenant_match compares exact strings; whitespace-padded ids must not equate.
    with pytest.raises(TenantIsolationError):
        assert_tenant_match(expected="org-a", presented="org-a ")
    with pytest.raises(TenantIsolationError):
        assert_tenant_match(expected="org-a", presented="ORG-A")


def test_empty_string_tenant_is_uncertainty_not_match() -> None:
    # Empty string is not None — still a mismatch against a real tenant.
    with pytest.raises(TenantIsolationError):
        assert_tenant_match(expected="org-a", presented="")


def test_content_length_zero_is_allowed_under_positive_ceiling() -> None:
    enforce_content_length(0, max_bytes=1024)
    with pytest.raises(RequestTooLargeError):
        enforce_content_length(1025, max_bytes=1024)
