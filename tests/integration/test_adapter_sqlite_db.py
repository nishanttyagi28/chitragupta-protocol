from __future__ import annotations

import pytest

from chitragupta.adapters.sqlite_db import RowEffectRequest, SQLiteRowAdapter


@pytest.fixture
def adapter(tmp_path):
    return SQLiteRowAdapter(str(tmp_path / "ledger.db"), table="ledger_accounts")


def _request(actor, principal, **kwargs):
    kwargs.setdefault("actor", actor)
    kwargs.setdefault("principal", principal)
    return RowEffectRequest(**kwargs)


def test_insert_then_verify(adapter, agent_principal, human_principal):
    req = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-1",
        new_balance=1000,
        idempotency_key="idem-insert-1",
    )
    manifest = adapter.prepare(req, context=None)
    precondition = adapter.validate_preconditions(manifest, context=None)
    assert precondition.satisfied
    result = adapter.commit(manifest, grant=None, context=None)
    assert result.success
    proof = adapter.verify(manifest, result, context=None)
    assert proof.matched_expected


def test_insert_duplicate_row_fails(adapter, agent_principal, human_principal):
    req = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-dup",
        new_balance=500,
        idempotency_key="idem-dup",
    )
    manifest = adapter.prepare(req, context=None)
    adapter.commit(manifest, grant=None, context=None)

    req2 = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-dup",
        new_balance=999,
        idempotency_key="idem-dup-2",
    )
    manifest2 = adapter.prepare(req2, context=None)
    precondition = adapter.validate_preconditions(manifest2, context=None)
    assert not precondition.satisfied


def test_update_with_optimistic_lock_succeeds(adapter, agent_principal, human_principal):
    insert_req = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-2",
        new_balance=1000,
        idempotency_key="idem-insert-2",
    )
    insert_manifest = adapter.prepare(insert_req, context=None)
    adapter.commit(insert_manifest, grant=None, context=None)

    update_req = _request(
        agent_principal,
        human_principal,
        operation="update",
        row_id="acct-2",
        new_balance=1500,
        idempotency_key="idem-update-2",
    )
    update_manifest = adapter.prepare(update_req, context=None)
    assert update_manifest.parameters["previous_balance"] == 1000
    result = adapter.commit(update_manifest, grant=None, context=None)
    assert result.success
    proof = adapter.verify(update_manifest, result, context=None)
    assert proof.matched_expected


def test_stale_version_detected_as_toctou(adapter, agent_principal, human_principal):
    insert_req = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-3",
        new_balance=1000,
        idempotency_key="idem-insert-3",
    )
    insert_manifest = adapter.prepare(insert_req, context=None)
    adapter.commit(insert_manifest, grant=None, context=None)

    update_req = _request(
        agent_principal,
        human_principal,
        operation="update",
        row_id="acct-3",
        new_balance=1200,
        idempotency_key="idem-update-3a",
    )
    stale_manifest = adapter.prepare(update_req, context=None)

    # Someone else updates the row between prepare() and commit().
    other_update_req = _request(
        agent_principal,
        human_principal,
        operation="update",
        row_id="acct-3",
        new_balance=1300,
        idempotency_key="idem-update-3b",
    )
    other_manifest = adapter.prepare(other_update_req, context=None)
    other_result = adapter.commit(other_manifest, grant=None, context=None)
    assert other_result.success

    precondition = adapter.validate_preconditions(stale_manifest, context=None)
    assert not precondition.satisfied
    assert "version changed" in precondition.reason


def test_delete_is_irreversible(adapter, agent_principal, human_principal):
    insert_req = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-4",
        new_balance=1000,
        idempotency_key="idem-insert-4",
    )
    insert_manifest = adapter.prepare(insert_req, context=None)
    adapter.commit(insert_manifest, grant=None, context=None)

    delete_req = _request(
        agent_principal,
        human_principal,
        operation="delete",
        row_id="acct-4",
        idempotency_key="idem-delete-4",
    )
    delete_manifest = adapter.prepare(delete_req, context=None)
    result = adapter.commit(delete_manifest, grant=None, context=None)
    assert result.success
    proof = adapter.verify(delete_manifest, result, context=None)
    assert proof.matched_expected  # row is indeed gone, as expected

    compensation = adapter.compensate(delete_manifest, result, context=None)
    assert compensation.attempted is False
    assert compensation.succeeded is False


def test_update_compensation_restores_previous_balance(adapter, agent_principal, human_principal):
    insert_req = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-5",
        new_balance=1000,
        idempotency_key="idem-insert-5",
    )
    insert_manifest = adapter.prepare(insert_req, context=None)
    adapter.commit(insert_manifest, grant=None, context=None)

    update_req = _request(
        agent_principal,
        human_principal,
        operation="update",
        row_id="acct-5",
        new_balance=2000,
        idempotency_key="idem-update-5",
    )
    update_manifest = adapter.prepare(update_req, context=None)
    result = adapter.commit(update_manifest, grant=None, context=None)
    assert result.success

    compensation = adapter.compensate(update_manifest, result, context=None)
    assert compensation.attempted
    assert compensation.succeeded

    verify_req = _request(
        agent_principal,
        human_principal,
        operation="update",
        row_id="acct-5",
        new_balance=1000,
        idempotency_key="idem-verify-restored",
    )
    verify_manifest = adapter.prepare(verify_req, context=None)
    assert verify_manifest.parameters["previous_balance"] == 1000


def test_insert_compensation_deletes_row(adapter, agent_principal, human_principal):
    req = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-6",
        new_balance=1000,
        idempotency_key="idem-insert-6",
    )
    manifest = adapter.prepare(req, context=None)
    result = adapter.commit(manifest, grant=None, context=None)
    compensation = adapter.compensate(manifest, result, context=None)
    assert compensation.succeeded

    reinsert_precondition_req = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-6",
        new_balance=1,
        idempotency_key="idem-reinsert-6",
    )
    reinsert_manifest = adapter.prepare(reinsert_precondition_req, context=None)
    precondition = adapter.validate_preconditions(reinsert_manifest, context=None)
    assert precondition.satisfied  # row is gone, so a fresh insert is valid again


def test_max_affected_rows_ceiling_is_configurable(tmp_path, agent_principal, human_principal):
    adapter = SQLiteRowAdapter(
        str(tmp_path / "ledger2.db"), table="ledger_accounts", max_affected_rows=1
    )
    req = _request(
        agent_principal,
        human_principal,
        operation="insert",
        row_id="acct-solo",
        new_balance=1,
        idempotency_key="idem-solo",
    )
    manifest = adapter.prepare(req, context=None)
    result = adapter.commit(manifest, grant=None, context=None)
    assert result.success  # single-row insert stays within the ceiling of 1
