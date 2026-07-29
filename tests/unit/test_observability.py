from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from karmasakshi.errors import SchemaVersionError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.observability import (
    InMemoryObservabilitySink,
    JsonlObservabilitySink,
    NullObservabilitySink,
    ObservabilityEvent,
    ObservabilityEventType,
    emit_safely,
)


def _make_event(**overrides: object) -> ObservabilityEvent:
    base: dict[str, object] = {
        "event_type": ObservabilityEventType.EFFECT_COMMITTED,
        "emitted_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "manifest_id": "m1",
    }
    base.update(overrides)
    return ObservabilityEvent(**base)  # type: ignore[arg-type]


def test_event_rejects_wrong_schema_version():
    with pytest.raises(SchemaVersionError):
        _make_event(schema_version="9.9")


def test_event_rejects_empty_manifest_id():
    with pytest.raises(ValueError, match="manifest_id"):
        _make_event(manifest_id="")


def test_event_rejects_oversized_detail():
    with pytest.raises(ValueError, match="detail"):
        _make_event(detail="x" * 2049)


def test_event_requires_tz_aware_timestamp():
    with pytest.raises(ValueError):
        _make_event(emitted_at=datetime(2026, 1, 1))  # naive


def test_null_sink_discards_silently():
    sink = NullObservabilitySink()
    sink.emit(_make_event())  # must not raise


def test_in_memory_sink_collects_in_order():
    sink = InMemoryObservabilitySink()
    e1 = _make_event(manifest_id="m1")
    e2 = _make_event(manifest_id="m2", event_type=ObservabilityEventType.EFFECT_VERIFIED)
    sink.emit(e1)
    sink.emit(e2)
    assert sink.events() == [e1, e2]


def test_jsonl_sink_appends_one_json_object_per_line(tmp_path):
    path = tmp_path / "events.jsonl"
    sink = JsonlObservabilitySink(path)
    sink.emit(_make_event(manifest_id="m1"))
    sink.emit(_make_event(manifest_id="m2"))
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    import json

    assert json.loads(lines[0])["manifest_id"] == "m1"
    assert json.loads(lines[1])["manifest_id"] == "m2"


def test_emit_safely_swallows_sink_exceptions():
    class BrokenSink:
        def emit(self, event: ObservabilityEvent) -> None:
            raise RuntimeError("disk full")

    emit_safely(BrokenSink(), _make_event())  # must not raise


def test_emit_safely_no_op_when_sink_is_none():
    emit_safely(None, _make_event())  # must not raise


# --- engine wiring ------------------------------------------------------------


def _authorize(engine, sealed, *, issuer, subject, issuer_signing_key, now, **overrides):
    kwargs = {
        "issuer": issuer,
        "subject": subject,
        "audience": ("payment.simulator",),
        "allowed_effect_types": (sealed.manifest.effect_type,),
        "scope": ScopeConstraints(),
        "not_before": now,
        "expires_at": now + timedelta(minutes=5),
        "signing_key": issuer_signing_key,
    }
    kwargs.update(overrides)
    return engine.authorize(sealed, **kwargs)


def test_engine_observe_forwards_to_configured_sink(
    engine_factory, manifest_factory, fake_adapter, issuer_signing_key
):
    sink = InMemoryObservabilitySink()
    engine = engine_factory()
    engine.context.observability_sink = sink
    manifest = manifest_factory(manifest_id="observe-1")
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)

    event = engine.observe(
        ObservabilityEventType.MANIFEST_PREPARED,
        sealed.manifest.manifest_id,
        manifest_hash=sealed.seal.manifest_hash,
    )
    assert event.lifecycle_state == "sealed"
    assert event.manifest_hash == sealed.seal.manifest_hash
    assert sink.events() == [event]


def test_engine_observe_is_a_no_op_without_a_sink(engine_factory, manifest_factory):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="observe-2")
    event = engine.observe(ObservabilityEventType.LIFECYCLE_FAILED, manifest.manifest_id)
    assert event.manifest_id == manifest.manifest_id


def test_engine_observe_never_raises_when_sink_is_broken(
    engine_factory, manifest_factory, fake_adapter, issuer_signing_key
):
    class BrokenSink:
        def emit(self, event: ObservabilityEvent) -> None:
            raise RuntimeError("network down")

    engine = engine_factory()
    engine.context.observability_sink = BrokenSink()
    manifest = manifest_factory(manifest_id="observe-3")
    event = engine.observe(ObservabilityEventType.EFFECT_COMMITTED, manifest.manifest_id)
    assert event.event_type == ObservabilityEventType.EFFECT_COMMITTED


def test_engine_observe_carries_tenant_id(engine_factory, manifest_factory):
    engine = engine_factory()
    engine.context.tenant_id = "tenant-z"
    manifest = manifest_factory(manifest_id="observe-4")
    event = engine.observe(ObservabilityEventType.EFFECT_VERIFIED, manifest.manifest_id)
    assert event.tenant_id == "tenant-z"
