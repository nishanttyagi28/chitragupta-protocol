"""Redis grant store tests.

These only run against a real, reachable Redis instance (checked via a raw
TCP probe against ``REDIS_URL``/localhost:6379). If none is reachable, every
test in this module is skipped with an explicit reason -- never silently
omitted from collection. See BUILD_STATUS.md for what was/wasn't executed
in a given run.
"""

from __future__ import annotations

import os
import socket
import threading
import uuid

import pytest

pytestmark = pytest.mark.redis


def _redis_reachable() -> tuple[bool, str]:
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    host = "localhost"
    port = 6379
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True, url
    except OSError as exc:
        return False, f"no Redis reachable at {host}:{port} ({exc})"


_REACHABLE, _REASON = _redis_reachable()


@pytest.fixture
def redis_client():
    if not _REACHABLE:
        pytest.skip(f"Redis integration test skipped: {_REASON}")
    import redis

    client = redis.Redis(host="localhost", port=6379, db=15)
    yield client
    client.flushdb()


@pytest.fixture
def store(redis_client):
    from chitragupta.stores.redis_store import RedisGrantStore

    return RedisGrantStore(redis_client, namespace=f"test-{uuid.uuid4().hex[:8]}")


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


def test_concurrent_reserve_at_most_one_thread_succeeds(store):
    results: list[bool] = []
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


def test_multi_use_ceiling(store):
    assert store.reserve("g1", max_uses=2) is True
    store.commit("g1", "idem-1", "ref-1")
    assert store.reserve("g1", max_uses=2) is True
    store.commit("g1", "idem-2", "ref-2")
    assert store.reserve("g1", max_uses=2) is False
