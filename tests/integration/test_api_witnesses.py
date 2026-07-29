"""API integration for independent witness quorum endpoints."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")

from fastapi.testclient import TestClient

from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV


@pytest.fixture
def dev_client(monkeypatch, tmp_path):
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    return TestClient(create_app(data_dir=tmp_path / "api-data"))


def _prepare_payment(client, idempotency_key="idem-witness-1"):
    body = {
        "adapter": "payment",
        "actor": {"principal_id": "agent-1", "principal_type": "agent"},
        "principal": {"principal_id": "user-1", "principal_type": "human"},
        "idempotency_key": idempotency_key,
        "fields": {
            "source_account": "acct-src",
            "beneficiary": "merchant-A",
            "amount_minor_units": 1000,
            "currency": "INR",
            "reference": idempotency_key,
        },
    }
    return client.post("/manifests/prepare", json=body)


def test_api_witness_submit_list_evaluate(dev_client):
    prep = _prepare_payment(dev_client)
    assert prep.status_code == 200, prep.text
    mid = prep.json()["manifest_id"]

    missing = dev_client.post(
        "/manifests/no-such/witnesses",
        json={
            "witness": {"principal_id": "alice", "principal_type": "human"},
            "observed_after_state_digest": "digest-1",
            "matched_expected": True,
            "required_witnesses": 1,
        },
    )
    assert missing.status_code == 404

    agent_rejected = dev_client.post(
        f"/manifests/{mid}/witnesses",
        json={
            "witness": {"principal_id": "bot", "principal_type": "agent"},
            "observed_after_state_digest": "digest-1",
            "matched_expected": True,
        },
    )
    assert agent_rejected.status_code == 422

    submitted = dev_client.post(
        f"/manifests/{mid}/witnesses",
        json={
            "witness": {"principal_id": "alice", "principal_type": "human"},
            "observed_after_state_digest": "digest-1",
            "matched_expected": True,
            "required_witnesses": 1,
        },
    )
    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["signature"] is not None

    listed = dev_client.get(f"/manifests/{mid}/witnesses")
    assert listed.status_code == 200
    assert len(listed.json()["statements"]) == 1

    evaluated = dev_client.post(
        f"/manifests/{mid}/witnesses/evaluate",
        json={
            "expected_after_state_digest": "digest-1",
            "actor": {"principal_id": "agent-1", "principal_type": "agent"},
            "subject": {"principal_id": "exec-1", "principal_type": "agent"},
            "required_witnesses": 1,
            "assert_quorum": True,
        },
    )
    assert evaluated.status_code == 200, evaluated.text
    assert evaluated.json()["satisfied"] is True
    assert evaluated.json()["witness_set_hash"] is not None

    not_met = dev_client.post(
        f"/manifests/{mid}/witnesses/evaluate",
        json={
            "expected_after_state_digest": "digest-1",
            "actor": {"principal_id": "agent-1", "principal_type": "agent"},
            "subject": {"principal_id": "exec-1", "principal_type": "agent"},
            "required_witnesses": 2,
            "assert_quorum": True,
        },
    )
    assert not_met.status_code == 403
