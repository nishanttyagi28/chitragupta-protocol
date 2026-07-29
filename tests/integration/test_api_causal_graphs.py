from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV


@pytest.fixture
def dev_client(monkeypatch, tmp_path):
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    return TestClient(create_app(data_dir=tmp_path / "api-data"))


def _prepare_payment(client, idempotency_key):
    return client.post(
        "/manifests/prepare",
        json={
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
        },
    )


def test_api_creates_and_reads_verified_causal_graph(dev_client):
    first = _prepare_payment(dev_client, idempotency_key="causal-parent").json()
    second = _prepare_payment(dev_client, idempotency_key="causal-child").json()
    response = dev_client.post(
        "/causal-graphs",
        json={
            "manifest_ids": [first["manifest_id"], second["manifest_id"]],
            "edges": [
                {
                    "parent_manifest_id": first["manifest_id"],
                    "child_manifest_id": second["manifest_id"],
                    "relation": "causes",
                }
            ],
        },
    )
    assert response.status_code == 200
    created = response.json()
    fetched = dev_client.get(f"/causal-graphs/{created['graph_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["verified"] is True
    assert fetched.json()["graph_hash"] == created["graph_hash"]


def test_api_rejects_cycle(dev_client):
    first = _prepare_payment(dev_client, idempotency_key="cycle-parent").json()
    second = _prepare_payment(dev_client, idempotency_key="cycle-child").json()
    response = dev_client.post(
        "/causal-graphs",
        json={
            "manifest_ids": [first["manifest_id"], second["manifest_id"]],
            "edges": [
                {
                    "parent_manifest_id": first["manifest_id"],
                    "child_manifest_id": second["manifest_id"],
                },
                {
                    "parent_manifest_id": second["manifest_id"],
                    "child_manifest_id": first["manifest_id"],
                },
            ],
        },
    )
    assert response.status_code == 422
