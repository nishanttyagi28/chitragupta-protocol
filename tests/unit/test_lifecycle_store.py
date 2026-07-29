"""Tests for durable lifecycle storage (Phase 13)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from karmasakshi.errors import StoreUnavailableError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.state_machine.states import LifecycleState
from karmasakshi.stores.lifecycle_memory import InMemoryLifecycleStore
from karmasakshi.stores.lifecycle_sqlite import SQLiteLifecycleStore


def test_memory_lifecycle_compare_and_set():
    store = InMemoryLifecycleStore()
    assert store.get("m1") is None
    assert store.compare_and_set("m1", None, LifecycleState.PREPARED) is True
    assert store.get("m1") == LifecycleState.PREPARED
    assert store.compare_and_set("m1", None, LifecycleState.SEALED) is False
    assert store.compare_and_set("m1", LifecycleState.PREPARED, LifecycleState.SEALED) is True
    assert store.get("m1") == LifecycleState.SEALED


def test_sqlite_lifecycle_persists_across_reopen(tmp_path: Path):
    path = tmp_path / "lifecycle.db"
    store = SQLiteLifecycleStore(path)
    store.set("m1", LifecycleState.AUTHORIZED)
    store.close()
    reopened = SQLiteLifecycleStore(path)
    assert reopened.get("m1") == LifecycleState.AUTHORIZED
    assert reopened.compare_and_set("m1", LifecycleState.AUTHORIZED, LifecycleState.COMMITTING)
    reopened.close()


def test_engine_write_through_and_hydrate(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
    keyring,
):
    from karmasakshi.audit.journal import AuditJournal
    from karmasakshi.engine import EngineContext, KarmaSakshiEngine
    from karmasakshi.stores.memory import InMemoryGrantStore

    durable = InMemoryLifecycleStore()
    engine = engine_factory(lifecycle_store=durable)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    assert durable.get(sealed.manifest.manifest_id) == LifecycleState.SEALED

    # Fresh engine + same store (simulates process restart with empty memory).
    restarted = KarmaSakshiEngine(
        EngineContext(
            keyring=keyring,
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=fixed_clock),
            clock=fixed_clock,
            lifecycle_store=durable,
        )
    )
    assert restarted.get_lifecycle_state(sealed.manifest.manifest_id) == LifecycleState.SEALED
    grant = restarted.authorize(
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
    assert durable.get(sealed.manifest.manifest_id) == LifecycleState.AUTHORIZED
    assert restarted.commit(sealed, grant, fake_adapter, context=None).success
    assert durable.get(sealed.manifest.manifest_id) == LifecycleState.COMMITTED


def test_lifecycle_store_outage_rolls_back_memory(
    engine_factory,
    manifest_factory,
    fake_adapter,
):
    class ExplodingStore:
        def get(self, manifest_id: str):
            return None

        def set(self, manifest_id: str, state: LifecycleState) -> None:
            raise StoreUnavailableError("boom")

        def compare_and_set(self, manifest_id, expected, new_state) -> bool:
            raise StoreUnavailableError("boom")

    engine = engine_factory(lifecycle_store=ExplodingStore())
    with pytest.raises(StoreUnavailableError):
        engine.prepare(fake_adapter, manifest_factory(), context=None)
    # Memory must not stay ahead of a failed durable write.
    assert engine.get_lifecycle_state(manifest_factory().manifest_id) == LifecycleState.PROPOSED


def test_sqlite_unknown_state_fails_closed(tmp_path: Path):
    path = tmp_path / "bad.db"
    store = SQLiteLifecycleStore(path)
    store._conn.execute(
        "INSERT INTO lifecycle_state(manifest_id, state) VALUES (?, ?)",
        ("m-bad", "not-a-real-state"),
    )
    store._conn.commit()
    with pytest.raises(StoreUnavailableError, match="unknown state"):
        store.get("m-bad")
    store.close()
