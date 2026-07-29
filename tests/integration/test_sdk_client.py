"""Sync Gateway SDK tests, run against a real uvicorn server in a
background thread (httpx's sync `Client` has no in-process ASGI
transport, unlike the async client -- see test_sdk_async_client.py for
the lighter-weight in-process equivalent). Skipped entirely if
fastapi/httpx/uvicorn are not installed."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")
pytest.importorskip("httpx")
pytest.importorskip("uvicorn")

import uvicorn

from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV
from karmasakshi.passports import ActionPassport, ActionPassportV2
from karmasakshi.portable import EvidencePack
from karmasakshi.sdk.client import GatewayClient
from karmasakshi.sdk.errors import KarmaSakshiApiError, KarmaSakshiSdkError


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def base_url(monkeypatch, tmp_path) -> Iterator[str]:
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    app = create_app(data_dir=tmp_path / "api-data")
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn server did not start in time"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def _bootstrap_and_login(client, org_id="acme", email="alice@acme.com", password="hunter2"):
    client.bootstrap_organization(
        org_id=org_id,
        name="Acme Corp",
        owner_email=email,
        owner_display_name="Alice",
        owner_password=password,
    )
    return client.login(org_id=org_id, email=email, password=password)


def test_full_refund_journey(base_url):
    with GatewayClient(base_url) as client:
        _bootstrap_and_login(client)
        assert client.session_token is not None

        me = client.me()
        assert me.email == "alice@acme.com"

        policy = client.activate_policy("acme", bundle_id="default-policy")
        assert policy.active is True

        proposal = client.propose_refund(
            "acme",
            agent_id="refund-agent-1",
            requested_by="customer-1",
            beneficiary="customer-acct-1",
            amount_minor_units=50000,
            reference="order-1",
            idempotency_key="idem-sync-1",
        )
        assert proposal.manifest_id
        assert 0 <= proposal.assessment.score <= 100
        assert proposal.assessment.signals

        pending = client.list_refunds("acme", decision_status="pending")
        assert [refund.manifest_id for refund in pending] == [proposal.manifest_id]
        detail = client.get_refund("acme", proposal.manifest_id)
        assert detail.effect.amount_minor_units == 50000
        assert detail.decision_status == "pending"

        approval = client.approve_refund("acme", proposal.manifest_id)
        assert approval.grant_id
        assert approval.policy_bundle_hash == policy.bundle_hash

        execution = client.execute_refund("acme", proposal.manifest_id, grant_id=approval.grant_id)
        assert execution.success is True

        verification = client.verify_refund("acme", proposal.manifest_id)
        assert verification.matched_expected is True

        passport = client.get_passport("acme", proposal.manifest_id)
        assert isinstance(passport, ActionPassport)
        assert passport.lifecycle_state == "verified"

        passport_v2 = client.get_passport("acme", proposal.manifest_id, version="v2")
        assert isinstance(passport_v2, ActionPassportV2)
        assert passport_v2.outcome_status.value == "verified_match"

        passport_html = client.get_passport_text("acme", proposal.manifest_id, fmt="html")
        assert proposal.manifest_id in passport_html

        pack = client.get_evidence_pack("acme", proposal.manifest_id)
        assert isinstance(pack, EvidencePack)
        result = client.verify_evidence_pack(pack)
        assert result.all_verified is True

        events = client.get_audit("acme")
        assert len(events) > 0
        assert client.verify_audit("acme") is True

        denied_proposal = client.propose_refund(
            "acme",
            agent_id="refund-agent-1",
            requested_by="customer-2",
            beneficiary="customer-acct-2",
            amount_minor_units=1000,
            reference="order-denied",
            idempotency_key="idem-sync-denied",
        )
        denial = client.deny_refund(
            "acme",
            denied_proposal.manifest_id,
            reason="Duplicate customer request",
        )
        assert denial.denied_by == "acme-owner"
        assert client.get_refund("acme", denied_proposal.manifest_id).decision_status == "denied"

        compensation = client.compensate_refund("acme", proposal.manifest_id)
        assert compensation.attempted is True
        assert compensation.succeeded is False

        new_user = client.create_user(
            "acme", user_id="u2", email="bob@acme.com", display_name="Bob", password="password123"
        )
        assert new_user.email == "bob@acme.com"
        assert {u.email for u in client.list_users("acme")} == {
            "alice@acme.com",
            "bob@acme.com",
        }

        org = client.get_organization("acme")
        assert org.org_id == "acme"
        assert client.logout().logged_out is True
        assert client.session_token is None


def test_grant_for_one_refund_cannot_execute_a_different_refund(base_url):
    with GatewayClient(base_url) as client:
        _bootstrap_and_login(client)
        proposal_a = client.propose_refund(
            "acme",
            agent_id="refund-agent-1",
            requested_by="customer-1",
            beneficiary="customer-acct-1",
            amount_minor_units=1000,
            reference="order-a",
            idempotency_key="idem-sync-a",
        )
        proposal_b = client.propose_refund(
            "acme",
            agent_id="refund-agent-1",
            requested_by="customer-1",
            beneficiary="customer-acct-1",
            amount_minor_units=999999,
            reference="order-b",
            idempotency_key="idem-sync-b",
        )
        approval_a = client.approve_refund("acme", proposal_a.manifest_id)
        with pytest.raises(KarmaSakshiApiError) as exc_info:
            client.execute_refund("acme", proposal_b.manifest_id, grant_id=approval_a.grant_id)
        assert exc_info.value.status_code == 409


def test_login_with_wrong_password_raises_api_error(base_url):
    with GatewayClient(base_url) as client:
        client.bootstrap_organization(
            org_id="acme",
            name="Acme Corp",
            owner_email="alice@acme.com",
            owner_display_name="Alice",
            owner_password="hunter2",
        )
        with pytest.raises(KarmaSakshiApiError) as exc_info:
            client.login(org_id="acme", email="alice@acme.com", password="wrong")
        assert exc_info.value.status_code == 401


def test_calling_session_endpoint_before_login_raises_sdk_error(base_url):
    with GatewayClient(base_url) as client, pytest.raises(KarmaSakshiSdkError):
        client.me()


def test_cross_tenant_rejected(base_url):
    with GatewayClient(base_url) as acme_client, GatewayClient(base_url) as beta_client:
        _bootstrap_and_login(acme_client, org_id="acme", email="alice@acme.com")
        _bootstrap_and_login(
            beta_client, org_id="beta", email="bob@beta.com", password="password123"
        )
        proposal = acme_client.propose_refund(
            "acme",
            agent_id="refund-agent-1",
            requested_by="customer-1",
            beneficiary="customer-acct-1",
            amount_minor_units=1000,
            reference="order-cross",
            idempotency_key="idem-sync-cross",
        )
        with pytest.raises(KarmaSakshiApiError) as exc_info:
            beta_client.get_passport("acme", proposal.manifest_id)
        assert exc_info.value.status_code == 403


def test_unreachable_gateway_raises_connection_error():
    from karmasakshi.sdk.errors import KarmaSakshiConnectionError

    port = _free_port()  # guaranteed free -- nothing is listening on it
    with (
        GatewayClient(f"http://127.0.0.1:{port}", timeout=2.0) as client,
        pytest.raises(KarmaSakshiConnectionError),
    ):
        client.bootstrap_organization(
            org_id="acme",
            name="Acme Corp",
            owner_email="alice@acme.com",
            owner_display_name="Alice",
            owner_password="hunter2",
        )
