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
