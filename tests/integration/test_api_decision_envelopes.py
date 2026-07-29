"""API Decision Envelope coverage (Phase 6)."""

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


def _envelope_body(**overrides):
    body = {
        "envelope_id": "env-api-1",
        "effect_type": "payment.transfer",
        "adapter_id": "payment",
        "adapter_version": "1.0",
        "target_resources": ["payment:beneficiary/merchant-A"],
        "constraints": {
            "amount_minor_units": {
                "kind": "integer_range",
                "min_int": 1,
                "max_int": 150_000,
            },
            "currency": {"kind": "enum", "allowed_values": ["INR"]},
            "beneficiary": {"kind": "exact", "exact_value": "merchant-A"},
        },
        "issuer": {"principal_id": "approver-1", "principal_type": "human"},
        "ttl_seconds": 3600,
        "max_cost_currency": "INR",
        "max_cost_minor_units": 200_000,
    }
    body.update(overrides)
    return body


def test_api_create_get_substitute_decision_envelope(dev_client):
    created = dev_client.post("/decision-envelopes", json=_envelope_body())
    assert created.status_code == 200
    payload = created.json()
    assert payload["envelope_id"] == "env-api-1"
    assert payload["envelope_hash"].startswith("sha256:")
    assert payload["signature"] is not None

    fetched = dev_client.get("/decision-envelopes/env-api-1")
    assert fetched.status_code == 200
    assert fetched.json()["verified"] is True
    assert fetched.json()["envelope_hash"] == payload["envelope_hash"]

    missing = dev_client.get("/decision-envelopes/no-such")
    assert missing.status_code == 404

    substituted = dev_client.post(
        "/decision-envelopes/env-api-1/substitute",
        json={"choices": {"amount_minor_units": 1000, "currency": "INR"}},
    )
    assert substituted.status_code == 200
    params = substituted.json()["parameters"]
    assert params["amount_minor_units"] == 1000
    assert params["beneficiary"] == "merchant-A"

    bad_sub = dev_client.post(
        "/decision-envelopes/env-api-1/substitute",
        json={"choices": {"currency": "USD"}},
    )
    assert bad_sub.status_code == 422

    missing_sub = dev_client.post(
        "/decision-envelopes/missing/substitute",
        json={"choices": {}},
    )
    assert missing_sub.status_code == 404


def test_api_envelope_constraint_kinds_and_errors(dev_client):
    monetary = dev_client.post(
        "/decision-envelopes",
        json=_envelope_body(
            envelope_id="env-mon",
            constraints={
                "amount": {
                    "kind": "monetary_range",
                    "currency": "INR",
                    "min_minor_units": 1,
                    "max_minor_units": 5000,
                }
            },
        ),
    )
    assert monetary.status_code == 200

    enum_empty = dev_client.post(
        "/decision-envelopes",
        json=_envelope_body(
            envelope_id="env-bad-enum",
            constraints={"currency": {"kind": "enum", "allowed_values": []}},
        ),
    )
    assert enum_empty.status_code == 422

    monetary_no_currency = dev_client.post(
        "/decision-envelopes",
        json=_envelope_body(
            envelope_id="env-bad-mon",
            constraints={
                "amount": {
                    "kind": "monetary_range",
                    "min_minor_units": 1,
                    "max_minor_units": 5,
                }
            },
        ),
    )
    assert monetary_no_currency.status_code == 422

    agent_issuer = dev_client.post(
        "/decision-envelopes",
        json=_envelope_body(
            envelope_id="env-agent",
            issuer={"principal_id": "agent-1", "principal_type": "agent"},
        ),
    )
    assert agent_issuer.status_code == 422


def test_api_envelope_with_missing_causal_graph(dev_client):
    response = dev_client.post(
        "/decision-envelopes",
        json=_envelope_body(envelope_id="env-graph-miss", causal_graph_id="missing-graph"),
    )
    assert response.status_code == 404


def test_api_approve_and_execute_with_decision_envelope(dev_client):
    prep = dev_client.post(
        "/manifests/prepare",
        json={
            "adapter": "payment",
            "actor": {"principal_id": "agent-1", "principal_type": "agent"},
            "principal": {"principal_id": "user-1", "principal_type": "human"},
            "idempotency_key": "idem-env-api-1",
            "fields": {
                "source_account": "acct-src",
                "beneficiary": "merchant-A",
                "amount_minor_units": 1000,
                "currency": "INR",
                "reference": "idem-env-api-1",
            },
        },
    )
    assert prep.status_code == 200
    manifest = prep.json()
    manifest_id = manifest["manifest_id"]

    # Discover target resource from sealed/prepared manifest listing if present
    detail = dev_client.get(f"/manifests/{manifest_id}")
    assert detail.status_code == 200
    m = detail.json()["manifest"]
    target = m["target_resource"]
    effect_type = m["effect_type"]
    adapter_id = m["adapter"]["adapter_id"]
    adapter_version = m["adapter"]["adapter_version"]
    param_constraints = {
        name: {"kind": "exact", "exact_value": value} for name, value in m["parameters"].items()
    }

    env = dev_client.post(
        "/decision-envelopes",
        json=_envelope_body(
            envelope_id="env-bind",
            effect_type=effect_type,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            target_resources=[target],
            constraints=param_constraints,
        ),
    )
    assert env.status_code == 200, env.text

    both = dev_client.post(
        f"/manifests/{manifest_id}/approve",
        json={
            "issuer": {"principal_id": "approver-1", "principal_type": "human"},
            "subject": {"principal_id": "agent-1", "principal_type": "agent"},
            "decision_envelope_id": "env-bind",
            "causal_graph_id": "g1",
        },
    )
    assert both.status_code == 422

    missing_env = dev_client.post(
        f"/manifests/{manifest_id}/approve",
        json={
            "issuer": {"principal_id": "approver-1", "principal_type": "human"},
            "subject": {"principal_id": "agent-1", "principal_type": "agent"},
            "decision_envelope_id": "nope",
        },
    )
    assert missing_env.status_code == 404

    approve = dev_client.post(
        f"/manifests/{manifest_id}/approve",
        json={
            "issuer": {"principal_id": "approver-1", "principal_type": "human"},
            "subject": {"principal_id": "agent-1", "principal_type": "agent"},
            "decision_envelope_id": "env-bind",
        },
    )
    assert approve.status_code == 200, approve.text
    grant_id = approve.json()["grant_id"]
    assert approve.json()["decision_envelope_hash"].startswith("sha256:")

    missing_at_exec = dev_client.post(
        f"/manifests/{manifest_id}/execute",
        json={"grant_id": grant_id},
    )
    # Engine commit failures are mapped to 409 Conflict.
    assert missing_at_exec.status_code == 409

    execute = dev_client.post(
        f"/manifests/{manifest_id}/execute",
        json={"grant_id": grant_id, "decision_envelope_id": "env-bind"},
    )
    assert execute.status_code == 200, execute.text
    assert execute.json()["success"] is True
