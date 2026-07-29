"""Redis audit backend tests (Phase 14).

Collected always; skipped with an explicit reason when Redis is unreachable.
"""

from __future__ import annotations

import os
import socket
import uuid

import pytest

from karmasakshi.audit.journal import AuditJournal
from karmasakshi.errors import AuditWriteError

pytestmark = pytest.mark.redis


def _redis_reachable() -> tuple[bool, str]:
    host = "localhost"
    port = 6379
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True, os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    except OSError as exc:
        return False, f"no Redis reachable at {host}:{port} ({exc})"


_REACHABLE, _REASON = _redis_reachable()


@pytest.fixture
def redis_client():
    if not _REACHABLE:
        pytest.skip(f"Redis integration test skipped: {_REASON}")
    import redis

    client = redis.Redis(host="localhost", port=6379, db=14)
    yield client
    client.flushdb()


@pytest.fixture
def redis_audit(redis_client):
    from karmasakshi.audit.redis_backend import RedisAuditBackend

    return RedisAuditBackend(redis_client, namespace=f"audit-{uuid.uuid4().hex[:8]}")


def test_redis_audit_roundtrip_and_chain(redis_audit, fixed_clock):
    journal = AuditJournal(backend=redis_audit, clock=fixed_clock)
    journal.record(event_type="t1", decision="allowed", manifest_id="m1")
    journal.record(event_type="t2", decision="allowed", manifest_id="m1")
    journal.verify_chain()
    assert len(journal.all_events()) == 2


def test_redis_audit_rejects_stale_sequence(redis_audit, fixed_clock):
    from karmasakshi.audit.events import AuditEvent
    from karmasakshi.canonical.serialize import canonical_hash

    journal = AuditJournal(backend=redis_audit, clock=fixed_clock)
    journal.record(event_type="t1", decision="allowed")
    # Craft a conflicting sequence-1 event and try to append directly.
    bogus = AuditEvent(
        sequence=1,
        event_id=AuditEvent.new_event_id(),
        previous_hash=None,
        timestamp=fixed_clock.now(),
        event_type="conflict",
        decision="blocked",
        metadata={},
    )
    bogus = bogus.model_copy(
        update={"event_hash": canonical_hash(bogus.model_dump(mode="json", exclude={"event_hash"}))}
    )
    with pytest.raises(AuditWriteError, match="rejected"):
        redis_audit.append(bogus)
