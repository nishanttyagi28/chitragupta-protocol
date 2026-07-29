"""API coverage for authorized compensation (Phase 7)."""

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


def _commit_payment(client, idempotency_key="idem-comp-api-1"):
    prep = client.post(
        "/manifests/prepare",
        json={
            "adapter": "payment",
            "actor": {"principal_id": "agent-1", "principal_type": "agent"},
            "principal": {"principal_id": "user-1", "principal_type": "human"},
            "idempotency_key": idempotency_key,
            "fields": {
                "source_account": "acct-src",
                "beneficiary": "merchant-A",
                "amount_minor_units": 500,
                "currency": "INR",
                "reference": idempotency_key,
            },
        },
    )
    assert prep.status_code == 200
    manifest_id = prep.json()["manifest_id"]
    approve = client.post(
        f"/manifests/{manifest_id}/approve",
        json={
            "issuer": {"principal_id": "approver-1", "principal_type": "human"},
            "subject": {"principal_id": "agent-1", "principal_type": "agent"},
        },
    )
    assert approve.status_code == 200
    grant_id = approve.json()["grant_id"]
    execute = client.post(
        f"/manifests/{manifest_id}/execute",
        json={"grant_id": grant_id},
    )
    assert execute.status_code == 200
    verify = client.post(f"/manifests/{manifest_id}/verify")
    assert verify.status_code == 200
    return manifest_id


def test_api_authorized_compensation_path(dev_client):
    manifest_id = _commit_payment(dev_client)
    prepared = dev_client.post(f"/manifests/{manifest_id}/compensation/prepare")
    assert prepared.status_code == 200, prepared.text
    compensation_id = prepared.json()["compensation_manifest_id"]
    assert prepared.json()["original_manifest_hash"].startswith("sha256:")

    authorize = dev_client.post(
        f"/manifests/{manifest_id}/compensation/{compensation_id}/authorize",
        json={
            "issuer": {"principal_id": "approver-1", "principal_type": "human"},
            "subject": {"principal_id": "agent-1", "principal_type": "agent"},
        },
    )
    assert authorize.status_code == 200, authorize.text
    grant_id = authorize.json()["grant_id"]

    agent_issuer = dev_client.post(
        f"/manifests/{manifest_id}/compensation/{compensation_id}/authorize",
        json={
            "issuer": {"principal_id": "agent-1", "principal_type": "agent"},
            "subject": {"principal_id": "agent-1", "principal_type": "agent"},
        },
    )
    assert agent_issuer.status_code == 422

    execute = dev_client.post(
        f"/manifests/{manifest_id}/compensation/{compensation_id}/execute",
        json={"grant_id": grant_id},
    )
    # Payment simulator honestly refuses compensation of settled payments
    # (attempted path still returns structured commit result from adapter.commit
    # on the compensation effect). Either success or honest failure is OK;
    # binding must have been accepted.
    assert execute.status_code == 200, execute.text

    passport = dev_client.get(f"/manifests/{manifest_id}/compensation/{compensation_id}/passport")
    assert passport.status_code == 200, passport.text
    body = passport.json()
    assert body["original_manifest_id"] == manifest_id
    assert body["compensation_manifest_id"] == compensation_id
    assert body["status"] in {"refused", "attempted", "verified"}
    assert body["seal_verified"] is True


def test_api_compensation_prepare_missing_original(dev_client):
    response = dev_client.post("/manifests/nope/compensation/prepare")
    assert response.status_code == 404
