"""Tests for transactional outbox (Phase 15)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.outbox import (
    InMemoryOutboxStore,
    OutboxConflictError,
    OutboxEntry,
    SQLiteOutboxStore,
)


def test_memory_outbox_pending_confirm_abandon(fixed_clock):
    store = InMemoryOutboxStore()
    entry = OutboxEntry(
        idempotency_key="k1",
        grant_id="g1",
        manifest_id="m1",
        manifest_hash="sha256:" + "a" * 64,
        status="pending",
        created_at=fixed_clock.now(),
    )
    store.record_pending(entry)
    assert store.get("k1") is not None
    assert store.list_pending()[0].idempotency_key == "k1"
    store.mark_confirmed("k1", "ref-1")
    assert store.get("k1").status == "confirmed"
    assert store.list_pending() == []


def test_sqlite_outbox_persists(tmp_path: Path, fixed_clock):
    path = tmp_path / "outbox.db"
    store = SQLiteOutboxStore(path)
    store.record_pending(
        OutboxEntry(
            idempotency_key="k2",
            grant_id="g2",
            manifest_id="m2",
            manifest_hash="sha256:" + "b" * 64,
            status="pending",
            created_at=fixed_clock.now(),
        )
    )
    store.close()
    reopened = SQLiteOutboxStore(path)
    assert reopened.get("k2").status == "pending"
    reopened.mark_abandoned("k2")
    assert reopened.get("k2").status == "abandoned"
    reopened.close()


def test_engine_commit_confirms_outbox(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    outbox = InMemoryOutboxStore()
    engine = engine_factory(outbox_store=outbox)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
    )
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success
    entry = outbox.get(sealed.manifest.idempotency_key)
    assert entry is not None
    assert entry.status == "confirmed"
    assert entry.outcome_ref == result.provider_reference


def test_adapter_crash_leaves_pending_outbox(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    outbox = InMemoryOutboxStore()
    engine = engine_factory(outbox_store=outbox)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
    )
    fake_adapter_state.raise_on_commit = True
    with pytest.raises(RuntimeError):
        engine.commit(sealed, grant, fake_adapter, context=None)
    entry = outbox.get(sealed.manifest.idempotency_key)
    assert entry is not None
    assert entry.status == "pending"
    assert engine.list_pending_outbox()


def test_recovery_confirms_pending_outbox(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    outbox = InMemoryOutboxStore()
    engine = engine_factory(outbox_store=outbox)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
    )
    fake_adapter_state.raise_on_commit = True
    with pytest.raises(RuntimeError):
        engine.commit(sealed, grant, fake_adapter, context=None)
    # Simulate that the external effect actually happened before the crash.
    fake_adapter_state.external_effects[sealed.manifest.idempotency_key] = "external-ref"
    proof = engine.recover_ambiguous_commit(sealed.manifest, fake_adapter, context=None)
    assert proof.matched_expected
    assert outbox.get(sealed.manifest.idempotency_key).status == "confirmed"


def test_failed_commit_abandons_outbox(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    outbox = InMemoryOutboxStore()
    engine = engine_factory(outbox_store=outbox)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
    )
    fake_adapter_state.fail_commit = True
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success is False
    assert outbox.get(sealed.manifest.idempotency_key).status == "abandoned"


def test_sqlite_outbox_edge_paths(tmp_path: Path, fixed_clock):
    path = tmp_path / "edges.db"
    store = SQLiteOutboxStore(path)
    entry = OutboxEntry(
        idempotency_key="edge",
        grant_id="g",
        manifest_id="m",
        manifest_hash="sha256:" + "d" * 64,
        status="pending",
        created_at=fixed_clock.now(),
    )
    store.record_pending(entry)
    store.record_pending(entry)  # idempotent re-record
    assert store.list_pending()
    store.mark_confirmed("edge", "ref")
    store.mark_confirmed("edge", "ref")  # idempotent
    with pytest.raises(OutboxConflictError):
        store.mark_abandoned("edge")
    with pytest.raises(OutboxConflictError):
        store.mark_confirmed("missing", "x")
    with pytest.raises(OutboxConflictError):
        store.record_pending(entry.model_copy(update={"status": "confirmed"}))
    # Corrupt status fails closed on read
    store._conn.execute(
        "INSERT INTO commit_outbox("
        "idempotency_key, grant_id, manifest_id, manifest_hash, status, "
        "created_at, outcome_ref, schema_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("bad", "g", "m", "sha256:" + "e" * 64, "weird", fixed_clock.now().isoformat(), None, "1.0"),
    )
    store._conn.commit()
    from karmasakshi.errors import StoreUnavailableError

    with pytest.raises(StoreUnavailableError, match="unknown status"):
        store.get("bad")
    store.close()


def test_stale_precondition_abandons_outbox(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    from karmasakshi.errors import StaleManifestError

    outbox = InMemoryOutboxStore()
    engine = engine_factory(outbox_store=outbox)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
    )
    fake_adapter_state.precondition_ok = False
    with pytest.raises(StaleManifestError):
        engine.commit(sealed, grant, fake_adapter, context=None)
    assert outbox.get(sealed.manifest.idempotency_key).status == "abandoned"


def test_sqlite_identity_mismatch_and_rerecord(tmp_path: Path, fixed_clock):
    store = SQLiteOutboxStore(tmp_path / "id.db")
    store.record_pending(
        OutboxEntry(
            idempotency_key="idk",
            grant_id="g1",
            manifest_id="m",
            manifest_hash="sha256:" + "1" * 64,
            status="pending",
            created_at=fixed_clock.now(),
        )
    )
    with pytest.raises(OutboxConflictError):
        store.record_pending(
            OutboxEntry(
                idempotency_key="idk",
                grant_id="g2",
                manifest_id="m",
                manifest_hash="sha256:" + "1" * 64,
                status="pending",
                created_at=fixed_clock.now(),
            )
        )
    store.mark_confirmed("idk", "ok")
    with pytest.raises(OutboxConflictError):
        store.record_pending(
            OutboxEntry(
                idempotency_key="idk",
                grant_id="g1",
                manifest_id="m",
                manifest_hash="sha256:" + "1" * 64,
                status="pending",
                created_at=fixed_clock.now(),
            )
        )
    with pytest.raises(OutboxConflictError):
        store.mark_abandoned("missing")
    store.close()


def test_memory_rerecord_after_confirm_rejected(fixed_clock):
    store = InMemoryOutboxStore()
    entry = OutboxEntry(
        idempotency_key="rr",
        grant_id="g",
        manifest_id="m",
        manifest_hash="sha256:" + "2" * 64,
        status="pending",
        created_at=fixed_clock.now(),
    )
    store.record_pending(entry)
    store.mark_confirmed("rr", "ref")
    with pytest.raises(OutboxConflictError):
        store.record_pending(entry)
    assert store.get("missing") is None

    store = InMemoryOutboxStore()
    with pytest.raises(OutboxConflictError):
        store.mark_confirmed("missing", "x")
    entry = OutboxEntry(
        idempotency_key="m",
        grant_id="g",
        manifest_id="mid",
        manifest_hash="sha256:" + "f" * 64,
        status="pending",
        created_at=fixed_clock.now(),
    )
    store.record_pending(entry)
    store.mark_abandoned("m")
    store.mark_abandoned("m")
    with pytest.raises(OutboxConflictError):
        store.mark_confirmed("m", "x")
    with pytest.raises(OutboxConflictError):
        store.record_pending(entry.model_copy(update={"status": "confirmed"}))

    store = InMemoryOutboxStore()
    store.record_pending(
        OutboxEntry(
            idempotency_key="k",
            grant_id="g1",
            manifest_id="m1",
            manifest_hash="sha256:" + "c" * 64,
            status="pending",
            created_at=fixed_clock.now(),
        )
    )
    with pytest.raises(OutboxConflictError):
        store.record_pending(
            OutboxEntry(
                idempotency_key="k",
                grant_id="g2",
                manifest_id="m1",
                manifest_hash="sha256:" + "c" * 64,
                status="pending",
                created_at=fixed_clock.now(),
            )
        )


def test_outbox_store_unavailable_blocks_commit(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    from karmasakshi.errors import StoreUnavailableError

    class BoomOutbox:
        def record_pending(self, entry):
            raise StoreUnavailableError("outbox down")

        def get(self, key):
            return None

        def mark_confirmed(self, key, ref):
            return None

        def mark_abandoned(self, key):
            return None

        def list_pending(self):
            return []

    engine = engine_factory(outbox_store=BoomOutbox())
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
    )
    with pytest.raises(StoreUnavailableError):
        engine.commit(sealed, grant, fake_adapter, context=None)


def test_list_pending_outbox_without_store(engine_factory):
    engine = engine_factory()
    assert engine.list_pending_outbox() == []


def test_precondition_exception_abandons_outbox(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    outbox = InMemoryOutboxStore()
    engine = engine_factory(outbox_store=outbox)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
    )

    def boom(*_a, **_k):
        raise RuntimeError("precondition boom")

    fake_adapter.validate_preconditions = boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="precondition boom"):
        engine.commit(sealed, grant, fake_adapter, context=None)
    assert outbox.get(sealed.manifest.idempotency_key).status == "abandoned"
