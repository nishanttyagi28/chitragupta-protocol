from __future__ import annotations

import pytest

from karmasakshi.errors import FailureMemoryCorruptedError
from karmasakshi.integrations.agenteval import (
    FailureMemoryStore,
    export_regression_fixture,
    failure_signature,
    failure_signature_for,
)


def _fixture(manifest_factory, now, *, failure_category="verification_mismatch", **overrides):
    manifest = manifest_factory(**overrides)
    return export_regression_fixture(manifest=manifest, failure_category=failure_category)


def test_empty_store_returns_no_fixtures(tmp_path):
    store = FailureMemoryStore(tmp_path / "memory.jsonl")
    assert store.all_fixtures() == []
    assert store.summarize() == []


def test_record_and_read_back_round_trips(tmp_path, manifest_factory, now):
    store = FailureMemoryStore(tmp_path / "nested" / "memory.jsonl")
    fixture = _fixture(manifest_factory, now, manifest_id="m1")
    store.record(fixture)
    fixtures = store.all_fixtures()
    assert len(fixtures) == 1
    assert fixtures[0] == fixture


def test_recurrence_count_groups_by_failure_shape(tmp_path, manifest_factory, now):
    store = FailureMemoryStore(tmp_path / "memory.jsonl")
    store.record(_fixture(manifest_factory, now, manifest_id="m1", idempotency_key="idem-1"))
    store.record(_fixture(manifest_factory, now, manifest_id="m2", idempotency_key="idem-2"))
    store.record(
        _fixture(
            manifest_factory,
            now,
            manifest_id="m3",
            idempotency_key="idem-3",
            failure_category="stale_manifest",
        )
    )

    count = store.recurrence_count(
        effect_type="payment.transfer",
        adapter_id="payment.simulator",
        failure_category="verification_mismatch",
        invariant=None,
    )
    assert count == 2

    other = store.recurrence_count(
        effect_type="payment.transfer",
        adapter_id="payment.simulator",
        failure_category="stale_manifest",
        invariant=None,
    )
    assert other == 1


def test_recurrence_count_distinguishes_by_invariant(tmp_path, manifest_factory, now):
    store = FailureMemoryStore(tmp_path / "memory.jsonl")
    manifest_a = manifest_factory(manifest_id="m1", idempotency_key="idem-a")
    manifest_b = manifest_factory(manifest_id="m2", idempotency_key="idem-b")
    store.record(
        export_regression_fixture(
            manifest=manifest_a, failure_category="verification_mismatch", invariant="#20"
        )
    )
    store.record(
        export_regression_fixture(
            manifest=manifest_b, failure_category="verification_mismatch", invariant="#21"
        )
    )

    assert (
        store.recurrence_count(
            effect_type="payment.transfer",
            adapter_id="payment.simulator",
            failure_category="verification_mismatch",
            invariant="#20",
        )
        == 1
    )
    assert (
        store.recurrence_count(
            effect_type="payment.transfer",
            adapter_id="payment.simulator",
            failure_category="verification_mismatch",
            invariant="#21",
        )
        == 1
    )
    assert (
        store.recurrence_count(
            effect_type="payment.transfer",
            adapter_id="payment.simulator",
            failure_category="verification_mismatch",
            invariant=None,
        )
        == 0
    )


def test_summarize_orders_by_occurrence_count_descending(tmp_path, manifest_factory, now):
    store = FailureMemoryStore(tmp_path / "memory.jsonl")
    for i in range(3):
        store.record(
            _fixture(
                manifest_factory,
                now,
                manifest_id=f"common-{i}",
                idempotency_key=f"idem-common-{i}",
                failure_category="verification_mismatch",
            )
        )
    store.record(
        _fixture(
            manifest_factory,
            now,
            manifest_id="rare-1",
            idempotency_key="idem-rare-1",
            failure_category="stale_manifest",
        )
    )

    summaries = store.summarize()
    assert len(summaries) == 2
    assert summaries[0].occurrence_count == 3
    assert summaries[0].failure_category == "verification_mismatch"
    assert summaries[1].occurrence_count == 1
    assert summaries[1].failure_category == "stale_manifest"


def test_failure_signature_is_deterministic_and_order_independent_of_dict_construction():
    sig1 = failure_signature_for(
        effect_type="payment.transfer",
        adapter_id="payment.simulator",
        failure_category="stale_manifest",
        invariant="#3",
    )
    sig2 = failure_signature_for(
        invariant="#3",
        failure_category="stale_manifest",
        adapter_id="payment.simulator",
        effect_type="payment.transfer",
    )
    assert sig1 == sig2


def test_failure_signature_differs_for_different_shapes():
    sig_a = failure_signature_for(
        effect_type="payment.transfer",
        adapter_id="payment.simulator",
        failure_category="stale_manifest",
        invariant=None,
    )
    sig_b = failure_signature_for(
        effect_type="payment.transfer",
        adapter_id="payment.simulator",
        failure_category="verification_mismatch",
        invariant=None,
    )
    assert sig_a != sig_b


def test_signature_matches_fixture_helper(manifest_factory, now):
    fixture = _fixture(manifest_factory, now, manifest_id="m1")
    expected = failure_signature_for(
        effect_type=fixture.effect_type,
        adapter_id=fixture.adapter_id,
        failure_category=fixture.failure_category,
        invariant=fixture.invariant,
    )
    assert failure_signature(fixture) == expected


def test_corrupted_line_raises_failure_memory_corrupted_error(tmp_path):
    path = tmp_path / "memory.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not valid json at all\n", encoding="utf-8")
    store = FailureMemoryStore(path)
    with pytest.raises(FailureMemoryCorruptedError):
        store.all_fixtures()


def test_blank_lines_are_skipped(tmp_path, manifest_factory, now):
    store = FailureMemoryStore(tmp_path / "memory.jsonl")
    fixture = _fixture(manifest_factory, now, manifest_id="m1")
    store.record(fixture)
    with store.path.open("a", encoding="utf-8") as fh:
        fh.write("\n\n")
    assert store.all_fixtures() == [fixture]


def test_store_is_unbounded_across_many_records(tmp_path, manifest_factory, now):
    store = FailureMemoryStore(tmp_path / "memory.jsonl")
    for i in range(50):
        store.record(
            _fixture(
                manifest_factory,
                now,
                manifest_id=f"bulk-{i}",
                idempotency_key=f"idem-bulk-{i}",
            )
        )
    assert len(store.all_fixtures()) == 50
    assert (
        store.recurrence_count(
            effect_type="payment.transfer",
            adapter_id="payment.simulator",
            failure_category="verification_mismatch",
            invariant=None,
        )
        == 50
    )
