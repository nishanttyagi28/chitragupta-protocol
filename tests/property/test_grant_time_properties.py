from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from chitragupta.errors import GrantExpiredError, GrantNotYetValidError
from chitragupta.grants.model import ExecutionGrant, ScopeConstraints
from chitragupta.grants.verifier import verify_grant_time_window

_BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _grant(not_before, expires_at) -> ExecutionGrant:
    return ExecutionGrant(
        grant_id="g1",
        manifest_hash="sha256:" + "a" * 64,
        issuer={"principal_id": "svc", "principal_type": "service"},
        subject={"principal_id": "agent-1", "principal_type": "agent"},
        audience=("adapter.x",),
        allowed_effect_types=("effect.x",),
        scope=ScopeConstraints(),
        issued_at=not_before,
        not_before=not_before,
        expires_at=expires_at,
        nonce="n1",
        key_id="k1",
        signature="unused",
    )


@given(
    st.integers(min_value=1, max_value=100_000),
    st.integers(min_value=-50_000, max_value=150_000),
    st.integers(min_value=0, max_value=60),
)
@settings(max_examples=300, deadline=None)
def test_time_window_boundary_matches_manual_computation(
    window_seconds, offset_seconds, leeway_seconds
):
    not_before = _BASE
    expires_at = _BASE + timedelta(seconds=window_seconds)
    grant = _grant(not_before, expires_at)
    now = _BASE + timedelta(seconds=offset_seconds)
    leeway = timedelta(seconds=leeway_seconds)

    earliest = not_before - leeway
    latest = expires_at + leeway

    if now < earliest:
        try:
            verify_grant_time_window(grant, now, leeway)
            failed_as_expected = False
        except GrantNotYetValidError:
            failed_as_expected = True
        assert failed_as_expected
    elif now > latest:
        try:
            verify_grant_time_window(grant, now, leeway)
            failed_as_expected = False
        except GrantExpiredError:
            failed_as_expected = True
        assert failed_as_expected
    else:
        verify_grant_time_window(grant, now, leeway)  # must not raise
