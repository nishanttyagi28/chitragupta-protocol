"""FastAPI control-plane tests. Skipped entirely if fastapi/jinja2 are not
installed (the optional ``api`` extra)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")

from fastapi.testclient import TestClient

from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV, TOKEN_ENV


@pytest.fixture
def dev_client(monkeypatch, tmp_path):
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    app = create_app(data_dir=tmp_path / "api-data")
    return TestClient(app)


def _prepare_payment(client, idempotency_key="idem-api-test-1", amount=1000):
    body = {
        "adapter": "payment",
        "actor": {"principal_id": "agent-1", "principal_type": "agent"},
        "principal": {"principal_id": "user-1", "principal_type": "human"},
        "idempotency_key": idempotency_key,
        "fields": {
            "source_account": "acct-src",
            "beneficiary": "merchant-A",
            "amount_minor_units": amount,
            "currency": "INR",
            "reference": idempotency_key,
        },
    }
    return client.post("/manifests/prepare", json=body)


def _approve(client, manifest_id):
    body = {
        "issuer": {"principal_id": "approver-1", "principal_type": "human"},
        "subject": {"principal_id": "agent-1", "principal_type": "agent"},
    }
    return client.post(f"/manifests/{manifest_id}/approve", json=body)


def test_health_and_ready(dev_client):
    assert dev_client.get("/health").json() == {"status": "ok"}
    ready = dev_client.get("/ready").json()
    assert ready["status"] == "ready"
    assert ready["dev_mode"] is True
    assert ready["audit_chain_verified"] is True


def test_full_lifecycle_happy_path(dev_client):
    prep = _prepare_payment(dev_client)
    assert prep.status_code == 200
    manifest_id = prep.json()["manifest_id"]

    listing = dev_client.get("/manifests").json()
    assert any(m["manifest_id"] == manifest_id for m in listing["manifests"])

    approve = _approve(dev_client, manifest_id)
    assert approve.status_code == 200
    grant_id = approve.json()["grant_id"]

    execute = dev_client.post(f"/manifests/{manifest_id}/execute", json={"grant_id": grant_id})
    assert execute.status_code == 200
    assert execute.json()["success"] is True

    verify = dev_client.post(f"/manifests/{manifest_id}/verify")
    assert verify.status_code == 200
    assert verify.json()["matched_expected"] is True

    passport = dev_client.get(f"/passports/{manifest_id}")
    assert passport.status_code == 200
    assert passport.json()["lifecycle_state"] == "verified"

    passport_md = dev_client.get(f"/passports/{manifest_id}", params={"fmt": "markdown"})
    assert "not a security certification" in passport_md.text


def test_deny_never_issues_grant(dev_client):
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-deny-1")
    manifest_id = prep.json()["manifest_id"]
    deny = dev_client.post(f"/manifests/{manifest_id}/deny", json={"reason": "policy"})
    assert deny.status_code == 200
    detail = dev_client.get(f"/manifests/{manifest_id}").json()
    assert detail["grant_ids"] == []


def test_revoked_grant_blocks_execute(dev_client):
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-revoke-1")
    manifest_id = prep.json()["manifest_id"]
    grant_id = _approve(dev_client, manifest_id).json()["grant_id"]

    revoke = dev_client.post(f"/grants/{grant_id}/revoke")
    assert revoke.status_code == 200
    assert revoke.json()["stopped_at_safepoint"] is True

    execute = dev_client.post(f"/manifests/{manifest_id}/execute", json={"grant_id": grant_id})
    assert execute.status_code == 409


def test_kill_switch_blocks_execution(dev_client):
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-kill-1")
    manifest_id = prep.json()["manifest_id"]
    grant_id = _approve(dev_client, manifest_id).json()["grant_id"]

    engage = dev_client.post("/kill-switch/engage")
    assert engage.json()["engaged"] is True

    execute = dev_client.post(f"/manifests/{manifest_id}/execute", json={"grant_id": grant_id})
    assert execute.status_code == 503

    disengage = dev_client.post("/kill-switch/disengage")
    assert disengage.json()["engaged"] is False

    execute2 = dev_client.post(f"/manifests/{manifest_id}/execute", json={"grant_id": grant_id})
    assert execute2.status_code == 200


def test_audit_endpoints(dev_client):
    _prepare_payment(dev_client, idempotency_key="idem-api-audit-1")
    events = dev_client.get("/audit").json()["events"]
    assert len(events) >= 2
    verify = dev_client.get("/audit/verify")
    assert verify.status_code == 200
    assert verify.json()["verified"] is True


def test_console_pages_render(dev_client):
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-console-1")
    manifest_id = prep.json()["manifest_id"]

    assert dev_client.get("/console/").status_code == 200
    assert dev_client.get(f"/console/manifests/{manifest_id}").status_code == 200
    assert dev_client.get("/console/grants").status_code == 200
    assert dev_client.get("/console/audit").status_code == 200


def test_console_approve_form_issues_grant(dev_client):
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-console-approve-1")
    manifest_id = prep.json()["manifest_id"]
    result = dev_client.post(
        f"/console/manifests/{manifest_id}/approve",
        data={
            "issuer_id": "approver-1",
            "issuer_type": "human",
            "subject_id": "agent-1",
            "max_uses": "1",
            "ttl_seconds": "300",
        },
        follow_redirects=False,
    )
    assert result.status_code == 303
    detail = dev_client.get(f"/manifests/{manifest_id}").json()
    assert len(detail["grant_ids"]) == 1


class TestAuthEnforcement:
    def test_missing_token_config_fails_closed(self, monkeypatch, tmp_path):
        monkeypatch.delenv(DEV_MODE_ENV, raising=False)
        monkeypatch.delenv(TOKEN_ENV, raising=False)
        app = create_app(data_dir=tmp_path / "api-data")
        client = TestClient(app)
        response = client.get("/manifests")
        assert response.status_code == 500

    def test_wrong_token_rejected(self, monkeypatch, tmp_path):
        monkeypatch.delenv(DEV_MODE_ENV, raising=False)
        monkeypatch.setenv(TOKEN_ENV, "correct-token")
        app = create_app(data_dir=tmp_path / "api-data")
        client = TestClient(app)
        response = client.get("/manifests", headers={"Authorization": "Bearer wrong-token"})
        assert response.status_code == 401

    def test_correct_token_accepted(self, monkeypatch, tmp_path):
        monkeypatch.delenv(DEV_MODE_ENV, raising=False)
        monkeypatch.setenv(TOKEN_ENV, "correct-token")
        app = create_app(data_dir=tmp_path / "api-data")
        client = TestClient(app)
        response = client.get("/manifests", headers={"Authorization": "Bearer correct-token"})
        assert response.status_code == 200

    def test_health_and_ready_never_require_auth(self, monkeypatch, tmp_path):
        monkeypatch.delenv(DEV_MODE_ENV, raising=False)
        monkeypatch.delenv(TOKEN_ENV, raising=False)
        app = create_app(data_dir=tmp_path / "api-data")
        client = TestClient(app)
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 200
