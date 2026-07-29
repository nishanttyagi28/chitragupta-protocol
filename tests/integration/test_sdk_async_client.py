"""Async Gateway SDK tests, run in-process against the real FastAPI app
via `httpx.ASGITransport` -- no real network server needed. Skipped
entirely if fastapi/httpx are not installed."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")
pytest.importorskip("httpx")

import httpx

from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV
from karmasakshi.gateway.models import GatewayUserRole
from karmasakshi.passports import ActionPassport, ActionPassportV2
from karmasakshi.portable import EvidencePack
from karmasakshi.sdk.async_client import AsyncGatewayClient
from karmasakshi.sdk.errors import KarmaSakshiApiError, KarmaSakshiSdkError


@pytest.fixture
def transport(monkeypatch, tmp_path):
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    app = create_app(data_dir=tmp_path / "api-data")
    return httpx.ASGITransport(app=app)


@pytest.fixture
def client(transport):
    return AsyncGatewayClient("http://testserver", transport=transport)


async def _bootstrap_and_login(client, org_id="acme", email="alice@acme.com", password="hunter2"):
    await client.bootstrap_organization(
        org_id=org_id,
        name="Acme Corp",
        owner_email=email,
        owner_display_name="Alice",
        owner_password=password,
    )
    return await client.login(org_id=org_id, email=email, password=password)


async def test_full_refund_journey(client):
    async with client:
        await _bootstrap_and_login(client)
        assert client.session_token is not None

        me = await client.me()
        assert me.email == "alice@acme.com"

        policy = await client.activate_policy("acme", bundle_id="default-policy")
        assert policy.active is True

        proposal = await client.propose_refund(
            "acme",
            agent_id="refund-agent-1",
            requested_by="customer-1",
            beneficiary="customer-acct-1",
            amount_minor_units=50000,
            reference="order-1",
            idempotency_key="idem-async-1",
        )
        assert proposal.manifest_id
        assert 0 <= proposal.assessment.score <= 100

        approval = await client.approve_refund("acme", proposal.manifest_id)
        assert approval.grant_id
        assert approval.policy_bundle_hash == policy.bundle_hash

        execution = await client.execute_refund(
            "acme", proposal.manifest_id, grant_id=approval.grant_id
        )
        assert execution.success is True

        verification = await client.verify_refund("acme", proposal.manifest_id)
        assert verification.matched_expected is True

        passport = await client.get_passport("acme", proposal.manifest_id)
        assert isinstance(passport, ActionPassport)
        assert passport.lifecycle_state == "verified"

        passport_v2 = await client.get_passport("acme", proposal.manifest_id, version="v2")
        assert isinstance(passport_v2, ActionPassportV2)
        assert passport_v2.outcome_status.value == "verified_match"

        passport_md = await client.get_passport_text("acme", proposal.manifest_id, fmt="markdown")
        assert "not a security certification" in passport_md

        pack = await client.get_evidence_pack("acme", proposal.manifest_id)
        assert isinstance(pack, EvidencePack)
        result = await client.verify_evidence_pack(pack)
        assert result.all_verified is True

        events = await client.get_audit("acme")
        assert len(events) > 0
        scoped_events = await client.get_audit("acme", manifest_id=proposal.manifest_id)
        assert all(e.manifest_id == proposal.manifest_id for e in scoped_events)
        assert await client.verify_audit("acme") is True

        compensation = await client.compensate_refund("acme", proposal.manifest_id)
        assert compensation.attempted is True
        assert compensation.succeeded is False

        users = await client.list_users("acme")
        assert {u.email for u in users} == {"alice@acme.com"}

        new_user = await client.create_user(
            "acme",
            user_id="u2",
            email="bob@acme.com",
            display_name="Bob",
            password="password123",
            role=GatewayUserRole.MEMBER,
        )
        assert new_user.email == "bob@acme.com"

        org = await client.get_organization("acme")
        assert org.org_id == "acme"


async def test_duplicate_execute_raises_api_error(client):
    async with client:
        await _bootstrap_and_login(client)
        proposal = await client.propose_refund(
            "acme",
            agent_id="refund-agent-1",
            requested_by="customer-1",
            beneficiary="customer-acct-1",
            amount_minor_units=1000,
            reference="order-dup",
            idempotency_key="idem-async-dup",
        )
        approval = await client.approve_refund("acme", proposal.manifest_id)
        await client.execute_refund("acme", proposal.manifest_id, grant_id=approval.grant_id)
        with pytest.raises(KarmaSakshiApiError) as exc_info:
            await client.execute_refund("acme", proposal.manifest_id, grant_id=approval.grant_id)
        assert exc_info.value.status_code == 409


async def test_login_with_wrong_password_raises_api_error(client):
    async with client:
        await client.bootstrap_organization(
            org_id="acme",
            name="Acme Corp",
            owner_email="alice@acme.com",
            owner_display_name="Alice",
            owner_password="hunter2",
        )
        with pytest.raises(KarmaSakshiApiError) as exc_info:
            await client.login(org_id="acme", email="alice@acme.com", password="wrong")
        assert exc_info.value.status_code == 401


async def test_calling_session_endpoint_before_login_raises_sdk_error(client):
    async with client:
        with pytest.raises(KarmaSakshiSdkError):
            await client.me()


async def test_cross_tenant_rejected(client, transport):
    async with client:
        await _bootstrap_and_login(client, org_id="acme", email="alice@acme.com")
        proposal = await client.propose_refund(
            "acme",
            agent_id="refund-agent-1",
            requested_by="customer-1",
            beneficiary="customer-acct-1",
            amount_minor_units=1000,
            reference="order-cross",
            idempotency_key="idem-async-cross",
        )

        other = AsyncGatewayClient("http://testserver", transport=transport)
        async with other:
            await other.bootstrap_organization(
                org_id="beta",
                name="Beta Corp",
                owner_email="bob@beta.com",
                owner_display_name="Bob",
                owner_password="password123",
            )
            await other.login(org_id="beta", email="bob@beta.com", password="password123")
            with pytest.raises(KarmaSakshiApiError) as exc_info:
                await other.get_passport("acme", proposal.manifest_id)
            assert exc_info.value.status_code == 403


async def test_verify_evidence_pack_works_without_a_session(client, transport):
    """The evidence-pack verify call hits a deliberately unauthenticated
    endpoint -- it must work even with no prior login on this client."""
    async with client:
        await _bootstrap_and_login(client)
        proposal = await client.propose_refund(
            "acme",
            agent_id="refund-agent-1",
            requested_by="customer-1",
            beneficiary="customer-acct-1",
            amount_minor_units=1000,
            reference="order-ep",
            idempotency_key="idem-async-ep",
        )
        approval = await client.approve_refund("acme", proposal.manifest_id)
        await client.execute_refund("acme", proposal.manifest_id, grant_id=approval.grant_id)
        pack = await client.get_evidence_pack("acme", proposal.manifest_id)

        fresh = AsyncGatewayClient("http://testserver", transport=transport)
        async with fresh:
            result = await fresh.verify_evidence_pack(pack)
            assert result.all_verified is True
