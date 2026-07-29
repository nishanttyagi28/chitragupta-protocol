"""Unit tests for Phase 14 audit backend abstraction (no Redis required)."""

from __future__ import annotations

import pytest

from karmasakshi.audit.base import AuditBackend
from karmasakshi.audit.journal import AuditJournal, InMemoryAuditBackend
from karmasakshi.audit.sqlite_backend import SQLiteAuditBackend
from karmasakshi.errors import AuditWriteError


def test_redis_backend_append_conflict_with_fake_client(fixed_clock):
    """Exercise RedisAuditBackend paths without a live Redis server."""
    from karmasakshi.audit.redis_backend import RedisAuditBackend
    from karmasakshi.audit.events import AuditEvent
    from karmasakshi.canonical.serialize import canonical_hash

    class FakeRedis:
        def __init__(self) -> None:
            self._list: list[str] = []

        def register_script(self, script: str):
            store = self

            def runner(*, keys, args):
                expected = int(args[1])
                if len(store._list) + 1 != expected:
                    return 0
                store._list.append(args[0])
                return 1

            return runner

        def lrange(self, key, start, end):
            return list(self._list)

        def lindex(self, key, index):
            if not self._list:
                return None
            return self._list[-1]

    client = FakeRedis()
    backend = RedisAuditBackend(client, namespace="fake")
    event = AuditEvent(
        sequence=1,
        event_id=AuditEvent.new_event_id(),
        previous_hash=None,
        timestamp=fixed_clock.now(),
        event_type="t",
        decision="allowed",
        metadata={},
    )
    event = event.model_copy(
        update={"event_hash": canonical_hash(event.model_dump(mode="json", exclude={"event_hash"}))}
    )
    backend.append(event)
    assert backend.last_event() is not None
    assert len(backend.all_events()) == 1
    with pytest.raises(AuditWriteError, match="rejected"):
        backend.append(event)


def test_backends_satisfy_protocol(tmp_path):
    memory = InMemoryAuditBackend()
    sqlite = SQLiteAuditBackend(tmp_path / "a.db")
    assert isinstance(memory, AuditBackend)
    assert isinstance(sqlite, AuditBackend)
    journal = AuditJournal(backend=sqlite)
    journal.record(event_type="x", decision="allowed")
    journal.verify_chain()
    sqlite.close()


def test_sqlite_duplicate_sequence_fails_closed(tmp_path, fixed_clock):
    path = tmp_path / "dup.db"
    backend = SQLiteAuditBackend(path)
    journal = AuditJournal(backend=backend, clock=fixed_clock)
    first = journal.record(event_type="a", decision="allowed")
    # Re-append same sequence via a second backend handle sharing the file.
    other = SQLiteAuditBackend(path)
    with pytest.raises(AuditWriteError):
        other.append(first)
    other.close()
    backend.close()
