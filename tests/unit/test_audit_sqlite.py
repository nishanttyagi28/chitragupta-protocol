from __future__ import annotations

import sqlite3

import pytest

from chitragupta.audit.journal import AuditJournal
from chitragupta.audit.sqlite_backend import SQLiteAuditBackend
from chitragupta.config.clock import FixedClock
from chitragupta.errors import AuditTamperedError


@pytest.fixture
def backend(tmp_path):
    b = SQLiteAuditBackend(tmp_path / "audit.db")
    yield b
    b.close()


def test_append_and_read_back(backend, now):
    journal = AuditJournal(backend=backend, clock=FixedClock(now))
    journal.record(event_type="a", decision="allowed", manifest_id="m1")
    journal.record(event_type="b", decision="allowed", manifest_id="m1")
    events = journal.all_events()
    assert len(events) == 2
    assert events[0].sequence == 1
    assert events[1].previous_hash == events[0].event_hash


def test_verify_chain_passes_when_untampered(backend, now):
    journal = AuditJournal(backend=backend, clock=FixedClock(now))
    journal.record(event_type="a", decision="allowed", manifest_id="m1")
    journal.record(event_type="b", decision="allowed", manifest_id="m1")
    journal.verify_chain()


def test_durability_across_reopen(tmp_path, now):
    path = tmp_path / "durable_audit.db"
    backend1 = SQLiteAuditBackend(path)
    journal1 = AuditJournal(backend=backend1, clock=FixedClock(now))
    journal1.record(event_type="a", decision="allowed", manifest_id="m1")
    journal1.record(event_type="b", decision="allowed", manifest_id="m1")
    backend1.close()

    backend2 = SQLiteAuditBackend(path)
    try:
        journal2 = AuditJournal(backend=backend2, clock=FixedClock(now))
        assert len(journal2.all_events()) == 2
        journal2.verify_chain()
        e3 = journal2.record(event_type="c", decision="allowed", manifest_id="m1")
        assert e3.sequence == 3
    finally:
        backend2.close()


def test_direct_file_tampering_is_detected(tmp_path, now):
    path = tmp_path / "tamper_audit.db"
    backend = SQLiteAuditBackend(path)
    journal = AuditJournal(backend=backend, clock=FixedClock(now))
    journal.record(event_type="a", decision="allowed", manifest_id="m1")
    journal.record(event_type="b", decision="allowed", manifest_id="m1")
    backend.close()

    # Tamper with row 1's payload directly via a separate raw connection,
    # bypassing the AuditJournal/SQLiteAuditBackend API entirely.
    raw_conn = sqlite3.connect(str(path))
    (payload,) = raw_conn.execute("SELECT payload FROM audit_events WHERE sequence = 1").fetchone()
    tampered_payload = payload.replace(b'"decision":"allowed"', b'"decision":"tampered"')
    assert tampered_payload != payload
    raw_conn.execute("UPDATE audit_events SET payload = ? WHERE sequence = 1", (tampered_payload,))
    raw_conn.commit()
    raw_conn.close()

    backend2 = SQLiteAuditBackend(path)
    try:
        journal2 = AuditJournal(backend=backend2, clock=FixedClock(now))
        with pytest.raises(AuditTamperedError):
            journal2.verify_chain()
    finally:
        backend2.close()
