from __future__ import annotations

import pytest

from chitragupta.audit import AuditJournal
from chitragupta.config import FixedClock
from chitragupta.errors import AuditTamperedError, AuditWriteError


def test_first_event_has_no_previous_hash(now):
    journal = AuditJournal(clock=FixedClock(now))
    event = journal.record(event_type="manifest.prepared", decision="allowed", manifest_id="m1")
    assert event.sequence == 1
    assert event.previous_hash is None
    assert event.event_hash


def test_chain_links_previous_hash(now):
    journal = AuditJournal(clock=FixedClock(now))
    e1 = journal.record(event_type="manifest.prepared", decision="allowed", manifest_id="m1")
    e2 = journal.record(event_type="manifest.sealed", decision="allowed", manifest_id="m1")
    assert e2.previous_hash == e1.event_hash
    assert e2.sequence == 2


def test_verify_chain_passes_when_untampered(now):
    journal = AuditJournal(clock=FixedClock(now))
    journal.record(event_type="a", decision="allowed", manifest_id="m1")
    journal.record(event_type="b", decision="allowed", manifest_id="m1")
    journal.record(event_type="c", decision="allowed", manifest_id="m1")
    journal.verify_chain()  # must not raise


def test_tampering_with_event_content_detected(now):
    journal = AuditJournal(clock=FixedClock(now))
    journal.record(event_type="a", decision="allowed", manifest_id="m1")
    journal.record(event_type="b", decision="allowed", manifest_id="m1")

    events = journal.all_events()
    tampered = events[0].model_copy(update={"decision": "denied"})
    events[0] = tampered
    # simulate an attacker mutating the backend's stored list directly
    journal._backend._events = events  # type: ignore[attr-defined]

    with pytest.raises(AuditTamperedError):
        journal.verify_chain()


def test_deleting_an_event_breaks_the_chain(now):
    journal = AuditJournal(clock=FixedClock(now))
    journal.record(event_type="a", decision="allowed", manifest_id="m1")
    journal.record(event_type="b", decision="allowed", manifest_id="m1")
    journal.record(event_type="c", decision="allowed", manifest_id="m1")

    events = journal.all_events()
    del events[1]
    journal._backend._events = events  # type: ignore[attr-defined]

    with pytest.raises(AuditTamperedError):
        journal.verify_chain()


def test_reordering_events_breaks_the_chain(now):
    journal = AuditJournal(clock=FixedClock(now))
    journal.record(event_type="a", decision="allowed", manifest_id="m1")
    journal.record(event_type="b", decision="allowed", manifest_id="m1")

    events = journal.all_events()
    events[0], events[1] = events[1], events[0]
    journal._backend._events = events  # type: ignore[attr-defined]

    with pytest.raises(AuditTamperedError):
        journal.verify_chain()


def test_events_for_manifest_filters_correctly(now):
    journal = AuditJournal(clock=FixedClock(now))
    journal.record(event_type="a", decision="allowed", manifest_id="m1")
    journal.record(event_type="b", decision="allowed", manifest_id="m2")
    journal.record(event_type="c", decision="allowed", manifest_id="m1")

    m1_events = journal.events_for_manifest("m1")
    assert len(m1_events) == 2
    assert all(e.manifest_id == "m1" for e in m1_events)


def test_backend_append_failure_raises_audit_write_error(now):
    class FailingBackend:
        def append(self, event):
            raise RuntimeError("disk full")

        def all_events(self):
            return []

        def last_event(self):
            return None

    journal = AuditJournal(backend=FailingBackend(), clock=FixedClock(now))
    with pytest.raises(AuditWriteError):
        journal.record(event_type="a", decision="allowed", manifest_id="m1")


def test_oversized_metadata_rejected(now):
    journal = AuditJournal(clock=FixedClock(now))
    with pytest.raises(ValueError):
        journal.record(
            event_type="a",
            decision="allowed",
            manifest_id="m1",
            metadata={f"k{i}": "v" for i in range(64)},
        )
