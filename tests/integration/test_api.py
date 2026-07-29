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


def _create_policy_bundle(client, bundle_id="bundle-1", **overrides):
    body = {
        "bundle_id": bundle_id,
        "issuer": {"principal_id": "policy-admin", "principal_type": "human"},
        **overrides,
    }
    return client.post("/policy/bundles", json=body)


def test_policy_bundle_create_get_and_verify(dev_client):
    created = _create_policy_bundle(dev_client)
    assert created.status_code == 200
    body = created.json()
    assert body["bundle"]["bundle_id"] == "bundle-1"
    assert body["seal"]["bundle_hash"].startswith("sha256:")

    fetched = dev_client.get("/policy/bundles/bundle-1")
    assert fetched.status_code == 200
    assert fetched.json()["seal"]["bundle_hash"] == body["seal"]["bundle_hash"]

    verified = dev_client.post("/policy/bundles/bundle-1/verify")
    assert verified.status_code == 200
    assert verified.json()["verified"] is True


def test_policy_bundle_create_rejects_agent_issuer(dev_client):
    resp = _create_policy_bundle(
        dev_client,
        bundle_id="bundle-agent",
        issuer={"principal_id": "agent-1", "principal_type": "agent"},
    )
    assert resp.status_code == 422


def test_policy_bundle_not_found_404s(dev_client):
    assert dev_client.get("/policy/bundles/does-not-exist").status_code == 404
    assert dev_client.post("/policy/bundles/does-not-exist/verify").status_code == 404


def test_approve_and_execute_bind_and_require_matching_policy_bundle(dev_client):
    _create_policy_bundle(dev_client, bundle_id="refund-policy")
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-policy-1")
    manifest_id = prep.json()["manifest_id"]

    approve = dev_client.post(
        f"/manifests/{manifest_id}/approve",
        json={
            "issuer": {"principal_id": "approver-1", "principal_type": "human"},
            "subject": {"principal_id": "agent-1", "principal_type": "agent"},
            "policy_bundle_id": "refund-policy",
        },
    )
    assert approve.status_code == 200
    grant_id = approve.json()["grant_id"]
    assert approve.json()["policy_bundle_hash"] is not None

    # Executing without the bound policy bundle must fail closed.
    execute_missing = dev_client.post(
        f"/manifests/{manifest_id}/execute", json={"grant_id": grant_id}
    )
    assert execute_missing.status_code == 409

    # Executing with the correct bundle succeeds.
    execute_ok = dev_client.post(
        f"/manifests/{manifest_id}/execute",
        json={"grant_id": grant_id, "policy_bundle_id": "refund-policy"},
    )
    assert execute_ok.status_code == 200
    assert execute_ok.json()["success"] is True

    passport = dev_client.get(f"/passports/{manifest_id}").json()
    assert passport["authorization_policy_bundle_hash"] is not None


def test_execute_with_swapped_policy_bundle_is_rejected(dev_client):
    _create_policy_bundle(dev_client, bundle_id="policy-a", block_threshold=85)
    _create_policy_bundle(dev_client, bundle_id="policy-b", block_threshold=10, review_threshold=0)
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-policy-2")
    manifest_id = prep.json()["manifest_id"]

    approve = dev_client.post(
        f"/manifests/{manifest_id}/approve",
        json={
            "issuer": {"principal_id": "approver-1", "principal_type": "human"},
            "subject": {"principal_id": "agent-1", "principal_type": "agent"},
            "policy_bundle_id": "policy-a",
        },
    )
    grant_id = approve.json()["grant_id"]

    execute = dev_client.post(
        f"/manifests/{manifest_id}/execute",
        json={"grant_id": grant_id, "policy_bundle_id": "policy-b"},
    )
    assert execute.status_code == 409


def test_assess_endpoint_records_and_is_retrievable(dev_client):
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-assess-1")
    manifest_id = prep.json()["manifest_id"]

    assess = dev_client.post(
        f"/manifests/{manifest_id}/assess",
        json={"cross_tenant": True, "policy_violations": ["kyc_pending"]},
    )
    assert assess.status_code == 200
    body = assess.json()
    assert body["recommendation"] == "block"
    assert any(s["name"] == "cross_tenant_effect" for s in body["signals"])

    fetched = dev_client.get(f"/manifests/{manifest_id}/assessment")
    assert fetched.status_code == 200
    assert fetched.json()["assessment_id"] == body["assessment_id"]

    audit = dev_client.get("/audit").json()
    assert any(
        e["event_type"] == "effect.assessed" and e["manifest_id"] == manifest_id
        for e in audit["events"]
    )


def test_assess_endpoint_unknown_manifest_404s(dev_client):
    resp = dev_client.post("/manifests/does-not-exist/assess", json={})
    assert resp.status_code == 404


def test_assessment_endpoint_before_assess_404s(dev_client):
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-assess-2")
    manifest_id = prep.json()["manifest_id"]
    resp = dev_client.get(f"/manifests/{manifest_id}/assessment")
    assert resp.status_code == 404


def test_passport_includes_assessment_when_present(dev_client):
    prep = _prepare_payment(dev_client, idempotency_key="idem-api-assess-3")
    manifest_id = prep.json()["manifest_id"]
    dev_client.post(f"/manifests/{manifest_id}/assess", json={})

    passport = dev_client.get(f"/passports/{manifest_id}")
    assert passport.status_code == 200
    body = passport.json()
    assert body["assessment_id"] is not None
    assert body["assessment_recommendation"] in {"allow", "review", "block"}

    passport_md = dev_client.get(f"/passports/{manifest_id}", params={"fmt": "markdown"})
    assert "Effect Intelligence Assessment" in passport_md.text


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
