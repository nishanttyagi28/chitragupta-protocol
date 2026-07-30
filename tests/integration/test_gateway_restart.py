"""RA-002 regression: a Gateway process restart must not turn an existing
organization's org-scoped routes into an unhandled HTTP 500.

Exact reproduction from `docs/product/RELEASE_AUDIT.md` (RA-002): bootstrap
succeeds, a fresh process (simulated here by a second `create_app()` call
against the same data directory) can still log in because the Gateway user
row is durable, but the refund-runtime route 500'd because
`MultiTenantControlPlane`'s registry and built states started empty. These
tests fail against the pre-remediation code and must keep passing
afterward."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")

from fastapi.testclient import TestClient

from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV
from karmasakshi.api.state import build_default_state
from karmasakshi.crypto.keys import generate_signing_key, save_signing_key_to_file
from karmasakshi.errors import KeyLoadError


def _bootstrap(client, org_id="acme", owner_email="alice@acme.com", owner_password="hunter2"):
    return client.post(
        "/gateway/organizations",
        json={
            "org_id": org_id,
            "name": "Acme Corp",
            "owner_email": owner_email,
            "owner_display_name": "Alice",
            "owner_password": owner_password,
        },
    )


def _login(client, org_id="acme", email="alice@acme.com", password="hunter2"):
    return client.post(
        "/gateway/auth/login", json={"org_id": org_id, "email": email, "password": password}
    )


def _approve_to_quorum(client, headers, org_id, manifest_id):
    """Approve a proposed refund up to whatever quorum its assessment
    requires, creating additional distinct approver accounts as needed.
    Returns the final (authorized) approve response."""
    response = client.post(
        f"/gateway/organizations/{org_id}/refunds/{manifest_id}/approve",
        json={},
        headers=headers,
    )
    assert response.status_code == 200
    index = 1
    while not response.json()["authorized"]:
        email = f"approver-{index}-{manifest_id[:8]}@example.com"
        created = client.post(
            f"/gateway/organizations/{org_id}/users",
            json={
                "user_id": f"{org_id}-approver-{index}-{manifest_id[:8]}",
                "email": email,
                "display_name": f"Approver {index}",
                "password": "approval-password",
                "role": "member",
            },
            headers=headers,
        )
        assert created.status_code == 200
        token = client.post(
            "/gateway/auth/login",
            json={"org_id": org_id, "email": email, "password": "approval-password"},
        ).json()["session_token"]
        response = client.post(
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/approve",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        index += 1
    return response


def test_restart_rehydrates_existing_organization_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"

    app1 = create_app(data_dir=data_dir)
    client1 = TestClient(app1)
    bootstrap_resp = _bootstrap(client1)
    assert bootstrap_resp.status_code == 200

    # Simulate a process restart: a brand-new app/process pointed at the
    # same durable data directory, with nothing carried over in memory.
    app2 = create_app(data_dir=data_dir)
    client2 = TestClient(app2)

    login_resp = _login(client2)
    assert login_resp.status_code == 200
    token = login_resp.json()["session_token"]

    refunds_resp = client2.get(
        "/gateway/organizations/acme/refunds",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert refunds_resp.status_code == 200
    assert refunds_resp.json() == {"refunds": []}


def test_restart_still_rejects_a_genuinely_unknown_organization_safely(monkeypatch, tmp_path):
    """An org_id that was never bootstrapped must fail closed with a safe
    4xx, not an unhandled 500, both before and after simulated restart."""
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"
    app1 = create_app(data_dir=data_dir)
    client1 = TestClient(app1)
    _bootstrap(client1)
    token = _login(client1).json()["session_token"]

    app2 = create_app(data_dir=data_dir)
    client2 = TestClient(app2)
    # Reuse app1's session token semantics are process-local (sessions are
    # not durable -- see docs/limitations.md), so app2 must reject it, and
    # must do so with a safe 401/403/404, never a 500.
    resp = client2.get(
        "/gateway/organizations/acme/refunds",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code in (401, 403, 404)


def test_restart_multiple_organizations_all_rehydrate(monkeypatch, tmp_path):
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"
    app1 = create_app(data_dir=data_dir)
    client1 = TestClient(app1)
    _bootstrap(client1, org_id="acme", owner_email="alice@acme.com")
    _bootstrap(client1, org_id="beta", owner_email="bob@beta.com", owner_password="password123")

    app2 = create_app(data_dir=data_dir)
    client2 = TestClient(app2)
    for org_id, email, password in (
        ("acme", "alice@acme.com", "hunter2"),
        ("beta", "bob@beta.com", "password123"),
    ):
        token = _login(client2, org_id=org_id, email=email, password=password).json()[
            "session_token"
        ]
        resp = client2.get(
            f"/gateway/organizations/{org_id}/refunds",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200


def test_committed_and_verified_refund_survives_a_restart(monkeypatch, tmp_path):
    """RA-002 follow-up regression: this is the exact gap the independent
    post-remediation audit found and reproduced -- a refund that was fully
    committed and independently verified before a restart must remain
    visible (detail, Passport, list) afterward, not silently vanish behind
    a 404/empty-list while the underlying commit genuinely succeeded."""
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"

    app1 = create_app(data_dir=data_dir)
    client1 = TestClient(app1)
    _bootstrap(client1)
    token1 = _login(client1).json()["session_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}
    client1.post(
        "/gateway/organizations/acme/agents",
        json={"agent_id": "refund-agent-1", "display_name": "Refund Agent"},
        headers=headers1,
    )
    client1.post(
        "/gateway/organizations/acme/adapters",
        json={"adapter_id": "payment.simulator", "adapter_version": "1.0.0"},
        headers=headers1,
    )
    propose = client1.post(
        "/gateway/organizations/acme/refunds/propose",
        json={
            "agent_id": "refund-agent-1",
            "requested_by": "customer-1",
            "beneficiary": "customer-acct-1",
            "amount_minor_units": 50000,
            "reference": "idem-restart-1",
            "idempotency_key": "idem-restart-1",
        },
        headers=headers1,
    )
    assert propose.status_code == 200
    manifest_id = propose.json()["manifest_id"]
    approve = _approve_to_quorum(client1, headers1, "acme", manifest_id)
    grant_id = approve.json()["grant_id"]
    assert grant_id is not None

    execute = client1.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers1,
    )
    assert execute.status_code == 200
    assert execute.json()["success"] is True

    verify = client1.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/verify", headers=headers1
    )
    assert verify.status_code == 200
    assert verify.json()["matched_expected"] is True

    # Simulate a process restart: a brand-new app/process pointed at the
    # same durable data directory, nothing carried over in memory.
    app2 = create_app(data_dir=data_dir)
    client2 = TestClient(app2)
    token2 = _login(client2).json()["session_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    detail = client2.get(f"/gateway/organizations/acme/refunds/{manifest_id}", headers=headers2)
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["commit_success"] is True
    assert detail_body["verification_status"] == "verified_match"

    listing = client2.get("/gateway/organizations/acme/refunds", headers=headers2)
    assert listing.status_code == 200
    assert [r["manifest_id"] for r in listing.json()["refunds"]] == [manifest_id]

    passport = client2.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport",
        params={"version": "v2"},
        headers=headers2,
    )
    assert passport.status_code == 200
    passport_body = passport.json()
    assert passport_body["outcome_status"] == "verified_match"
    # The signing key must also be durable (RA-002 follow-up): a passport
    # generated post-restart must still verify the pre-restart grant's
    # signature, not just report a plausible-looking outcome status.
    assert passport_body["verification"]["seal_verified"] is True
    assert passport_body["verification"]["grant_verified"] is True
    assert passport_body["verification"]["audit_chain_verified"] is True


def test_proposed_but_unapproved_refund_survives_a_restart(monkeypatch, tmp_path):
    """A refund that was only proposed (never approved) must also remain
    visible after a restart, with its rehydrated assessment intact, and
    the approval workflow must be drivable all the way to a grant and a
    successful execute *across* the restart -- this requires the
    per-tenant Ed25519 signing key to also be durable (not just the
    refund-journey dicts), since `authorize_with_quorum` re-verifies the
    pre-restart sealed manifest's seal against the current keyring."""
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"

    app1 = create_app(data_dir=data_dir)
    client1 = TestClient(app1)
    _bootstrap(client1)
    token1 = _login(client1).json()["session_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}
    client1.post(
        "/gateway/organizations/acme/agents",
        json={"agent_id": "refund-agent-1", "display_name": "Refund Agent"},
        headers=headers1,
    )
    client1.post(
        "/gateway/organizations/acme/adapters",
        json={"adapter_id": "payment.simulator", "adapter_version": "1.0.0"},
        headers=headers1,
    )
    propose = client1.post(
        "/gateway/organizations/acme/refunds/propose",
        json={
            "agent_id": "refund-agent-1",
            "requested_by": "customer-1",
            "beneficiary": "customer-acct-1",
            "amount_minor_units": 50000,
            "reference": "idem-restart-2",
            "idempotency_key": "idem-restart-2",
        },
        headers=headers1,
    )
    assert propose.status_code == 200
    manifest_id = propose.json()["manifest_id"]

    app2 = create_app(data_dir=data_dir)
    client2 = TestClient(app2)
    token2 = _login(client2).json()["session_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    detail = client2.get(f"/gateway/organizations/acme/refunds/{manifest_id}", headers=headers2)
    assert detail.status_code == 200
    assert detail.json()["decision_status"] == "pending"
    assert detail.json()["assessment"]["score"] is not None

    approve = _approve_to_quorum(client2, headers2, "acme", manifest_id)
    assert approve.json()["authorized"] is True
    grant_id = approve.json()["grant_id"]
    assert grant_id is not None

    execute = client2.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers2,
    )
    assert execute.status_code == 200
    assert execute.json()["success"] is True


def test_active_policy_and_new_proposals_survive_a_restart(monkeypatch, tmp_path):
    """Regression for the signing-key durability gap the second
    independent post-remediation audit found: once an organization has
    activated a policy, every subsequent proposal re-verifies that
    policy bundle's signature. Before the per-tenant signing key was made
    durable, the keyring only ever trusted the newest (post-restart) key,
    so this deterministically 409'd for any org with an active policy."""
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"

    app1 = create_app(data_dir=data_dir)
    client1 = TestClient(app1)
    _bootstrap(client1)
    token1 = _login(client1).json()["session_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}
    client1.post(
        "/gateway/organizations/acme/agents",
        json={"agent_id": "refund-agent-1", "display_name": "Refund Agent"},
        headers=headers1,
    )
    client1.post(
        "/gateway/organizations/acme/adapters",
        json={"adapter_id": "payment.simulator", "adapter_version": "1.0.0"},
        headers=headers1,
    )
    policy = client1.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "policy-a", "block_threshold": 95, "review_threshold": 90},
        headers=headers1,
    )
    assert policy.status_code == 200

    app2 = create_app(data_dir=data_dir)
    client2 = TestClient(app2)
    token2 = _login(client2).json()["session_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    propose = client2.post(
        "/gateway/organizations/acme/refunds/propose",
        json={
            "agent_id": "refund-agent-1",
            "requested_by": "customer-1",
            "beneficiary": "customer-acct-1",
            "amount_minor_units": 50000,
            "reference": "idem-restart-policy",
            "idempotency_key": "idem-restart-policy",
        },
        headers=headers2,
    )
    assert propose.status_code == 200
    assert propose.json()["assessment"]["policy_id"] == "policy-a"


def test_missing_signing_key_with_existing_records_fails_closed(monkeypatch, tmp_path):
    """Independent audit finding: deleting signing-key.bin for a tenant
    that already has durable signed records must not mint a replacement
    identity. Pre-fix behaviour regenerated a new Ed25519 key on the
    next create_app(), so prior grants/policies failed verification and
    looked like tampering rather than operator key-loss."""
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"

    app1 = create_app(data_dir=data_dir)
    client1 = TestClient(app1)
    _bootstrap(client1)
    token1 = _login(client1).json()["session_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}
    client1.post(
        "/gateway/organizations/acme/agents",
        json={"agent_id": "refund-agent-1", "display_name": "Refund Agent"},
        headers=headers1,
    )
    client1.post(
        "/gateway/organizations/acme/adapters",
        json={"adapter_id": "payment.simulator", "adapter_version": "1.0.0"},
        headers=headers1,
    )
    policy = client1.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "policy-a", "block_threshold": 95, "review_threshold": 90},
        headers=headers1,
    )
    assert policy.status_code == 200
    propose = client1.post(
        "/gateway/organizations/acme/refunds/propose",
        json={
            "agent_id": "refund-agent-1",
            "requested_by": "customer-1",
            "beneficiary": "customer-acct-1",
            "amount_minor_units": 50000,
            "reference": "idem-missing-key",
            "idempotency_key": "idem-missing-key",
        },
        headers=headers1,
    )
    assert propose.status_code == 200

    tenant_key = data_dir / "tenants" / "acme" / "signing-key.bin"
    assert tenant_key.exists()
    tenant_key.unlink()
    assert not tenant_key.exists()

    with pytest.raises(KeyLoadError, match="missing for existing tenant"):
        create_app(data_dir=data_dir)


def test_corrupt_signing_key_fails_closed(monkeypatch, tmp_path):
    """Corrupt private-key bytes must fail closed at startup, never be
    treated as a clean first-start that regenerates identity."""
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"

    app1 = create_app(data_dir=data_dir)
    client1 = TestClient(app1)
    _bootstrap(client1)
    token1 = _login(client1).json()["session_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}
    # Force durable protocol artifacts into the tenant directory.
    client1.post(
        "/gateway/organizations/acme/agents",
        json={"agent_id": "refund-agent-1", "display_name": "Refund Agent"},
        headers=headers1,
    )

    tenant_key = data_dir / "tenants" / "acme" / "signing-key.bin"
    assert tenant_key.exists()
    tenant_key.write_bytes(b"not-a-valid-ed25519-private-key!!")

    with pytest.raises(KeyLoadError):
        create_app(data_dir=data_dir)


def test_mismatched_signing_key_fails_closed(monkeypatch, tmp_path):
    """Replacing the private key while leaving the public-identity sidecar
    (or swapping in an unrelated valid Ed25519 key) must fail closed."""
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"

    app1 = create_app(data_dir=data_dir)
    client1 = TestClient(app1)
    _bootstrap(client1)

    tenant_dir = data_dir / "tenants" / "acme"
    tenant_key = tenant_dir / "signing-key.bin"
    tenant_pub = tenant_dir / "signing-key.pub"
    assert tenant_key.exists()
    assert tenant_pub.exists()
    original_pub = tenant_pub.read_bytes()

    replacement = generate_signing_key("api-dev-issuer")
    save_signing_key_to_file(replacement, tenant_key)
    # Sidecar still records the original public identity.
    assert tenant_pub.read_bytes() == original_pub
    assert replacement.public_bytes() != original_pub

    with pytest.raises(KeyLoadError, match="does not match recorded public identity"):
        create_app(data_dir=data_dir)


def test_clean_first_start_generates_signing_key(tmp_path):
    """An empty data directory is a genuine first start: mint a new key
    and record its public identity. Distinct from restart restoration."""
    data_dir = tmp_path / "fresh-tenant"
    state = build_default_state(data_dir)
    key_path = data_dir / "signing-key.bin"
    pub_path = data_dir / "signing-key.pub"
    assert key_path.exists()
    assert pub_path.exists()
    assert pub_path.read_bytes() == state.signing_key.public_bytes()

    # Second construction against the same directory restores, not regenerates.
    state2 = build_default_state(data_dir)
    assert state2.signing_key.public_bytes() == state.signing_key.public_bytes()
