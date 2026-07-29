from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from karmasakshi.config.clock import FixedClock
from karmasakshi.gateway.models import GatewayUser, GatewayUserRole
from karmasakshi.gateway.sessions import GatewaySessionStore


@pytest.fixture
def user() -> GatewayUser:
    return GatewayUser(
        user_id="u1",
        org_id="org-1",
        email="alice@acme.com",
        display_name="Alice",
        role=GatewayUserRole.OWNER,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_issue_returns_a_session_bound_to_the_user(user, clock):
    store = GatewaySessionStore(clock=clock)
    session = store.issue(user)
    assert session.user_id == user.user_id
    assert session.org_id == user.org_id
    assert session.issued_at == clock.now()


def test_issued_tokens_are_unique(user, clock):
    store = GatewaySessionStore(clock=clock)
    s1 = store.issue(user)
    s2 = store.issue(user)
    assert s1.token != s2.token


def test_get_returns_the_issued_session(user, clock):
    store = GatewaySessionStore(clock=clock)
    session = store.issue(user)
    fetched = store.get(session.token)
    assert fetched == session


def test_get_returns_none_for_unknown_token(clock):
    store = GatewaySessionStore(clock=clock)
    assert store.get("no-such-token") is None


def test_session_expires_after_ttl(user, clock):
    store = GatewaySessionStore(ttl=timedelta(hours=1), clock=clock)
    session = store.issue(user)
    clock.advance(timedelta(hours=1))
    assert store.get(session.token) is None


def test_session_valid_just_before_expiry(user, clock):
    store = GatewaySessionStore(ttl=timedelta(hours=1), clock=clock)
    session = store.issue(user)
    clock.advance(timedelta(minutes=59, seconds=59))
    assert store.get(session.token) == session


def test_expired_session_is_evicted_not_just_rejected(user, clock):
    store = GatewaySessionStore(ttl=timedelta(hours=1), clock=clock)
    session = store.issue(user)
    clock.advance(timedelta(hours=2))
    assert store.get(session.token) is None
    # internal dict no longer holds the stale entry
    assert session.token not in store._sessions


def test_revoke_invalidates_the_session(user, clock):
    store = GatewaySessionStore(clock=clock)
    session = store.issue(user)
    store.revoke(session.token)
    assert store.get(session.token) is None


def test_revoke_unknown_token_is_a_no_op(clock):
    store = GatewaySessionStore(clock=clock)
    store.revoke("no-such-token")  # must not raise


def test_revoke_all_for_user_clears_every_session(user, clock):
    store = GatewaySessionStore(clock=clock)
    s1 = store.issue(user)
    s2 = store.issue(user)
    store.revoke_all_for_user(user.user_id)
    assert store.get(s1.token) is None
    assert store.get(s2.token) is None


def test_revoke_all_for_user_does_not_affect_other_users(clock):
    store = GatewaySessionStore(clock=clock)
    user_a = GatewayUser(
        user_id="a",
        org_id="org-1",
        email="a@acme.com",
        display_name="A",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    user_b = GatewayUser(
        user_id="b",
        org_id="org-1",
        email="b@acme.com",
        display_name="B",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    session_a = store.issue(user_a)
    session_b = store.issue(user_b)
    store.revoke_all_for_user("a")
    assert store.get(session_a.token) is None
    assert store.get(session_b.token) == session_b


def test_is_expired_boundary():
    session = GatewaySessionStore().issue(
        GatewayUser(
            user_id="u1",
            org_id="org-1",
            email="a@b.com",
            display_name="A",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    )
    assert session.is_expired(session.expires_at) is True
    assert session.is_expired(session.expires_at - timedelta(seconds=1)) is False
