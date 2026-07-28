from __future__ import annotations

import threading

import pytest

from chitragupta.errors import StoreUnavailableError
from chitragupta.stores.sqlite import SQLiteGrantStore


@pytest.fixture
def store(tmp_path):
    s = SQLiteGrantStore(tmp_path / "grants.db")
    yield s
    s.close()


def test_reserve_and_commit_roundtrip(store):
    assert store.reserve("g1", max_uses=1) is True
    store.commit("g1", "idem-1", "ref-1")
    assert store.get_use_count("g1") == 1
    assert store.get_idempotent_outcome("idem-1") == "ref-1"


def test_single_use_cannot_be_reserved_twice(store):
    assert store.reserve("g1", max_uses=1) is True
    store.commit("g1", "idem-1", "ref-1")
    assert store.reserve("g1", max_uses=1) is False


def test_release_does_not_consume_a_use(store):
    assert store.reserve("g1", max_uses=1) is True
    store.release("g1")
    assert store.get_use_count("g1") == 0
    assert store.reserve("g1", max_uses=1) is True


def test_revoke_blocks_future_reservation(store):
    store.revoke("g1")
    assert store.is_revoked("g1") is True
    assert store.reserve("g1", max_uses=5) is False


def test_revoke_before_any_reservation_works(store):
    # revoking a grant_id the store has never seen must still work (preemptive revoke)
    store.revoke("never-seen")
    assert store.is_revoked("never-seen") is True


def test_commit_without_reservation_raises(store):
    with pytest.raises(StoreUnavailableError):
        store.commit("g1", "idem-1", "ref-1")


def test_durability_across_store_reopen(tmp_path):
    path = tmp_path / "durable.db"
    store1 = SQLiteGrantStore(path)
    store1.reserve("g1", max_uses=1)
    store1.commit("g1", "idem-1", "ref-1")
    store1.close()

    store2 = SQLiteGrantStore(path)
    try:
        assert store2.get_use_count("g1") == 1
        assert store2.get_idempotent_outcome("idem-1") == "ref-1"
        assert store2.reserve("g1", max_uses=1) is False
    finally:
        store2.close()


def test_concurrent_reserve_at_most_one_thread_succeeds(store):
    results = []
    barrier = threading.Barrier(10)

    def attempt():
        barrier.wait()
        results.append(store.reserve("shared", max_uses=1))

    threads = [threading.Thread(target=attempt) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(results) == 1


def test_record_idempotent_outcome_without_grant(store):
    store.record_idempotent_outcome("idem-standalone", "ref-standalone")
    assert store.get_idempotent_outcome("idem-standalone") == "ref-standalone"


def test_backend_failure_fails_closed_on_every_mutating_method(tmp_path):
    """Simulate a broken backend connection (closed database) and confirm
    every mutating method translates the raw sqlite3.Error into
    StoreUnavailableError rather than leaking it or silently succeeding."""
    s = SQLiteGrantStore(tmp_path / "broken.db")
    s._conn.close()  # simulate the connection dying underneath the store
    with pytest.raises(StoreUnavailableError):
        s.reserve("g1", 1)
    with pytest.raises(StoreUnavailableError):
        s.release("g1")
    with pytest.raises(StoreUnavailableError):
        s.commit("g1", "idem-1", "ref-1")
    with pytest.raises(StoreUnavailableError):
        s.revoke("g1")
    with pytest.raises(StoreUnavailableError):
        s.record_idempotent_outcome("idem-1", "ref-1")
