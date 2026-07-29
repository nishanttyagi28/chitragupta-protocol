"""Gateway HTTP API tests (Milestone A). Skipped entirely if fastapi is
not installed (the optional ``api`` extra)."""

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


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_bootstrap_organization_creates_org_and_owner(dev_client):
    resp = _bootstrap(dev_client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["organization"]["org_id"] == "acme"
    assert body["organization"]["status"] == "active"
    assert body["owner"]["email"] == "alice@acme.com"
    assert body["owner"]["role"] == "owner"


def test_bootstrap_duplicate_organization_conflicts(dev_client):
    _bootstrap(dev_client)
    resp = _bootstrap(dev_client)
    assert resp.status_code == 409


def test_bootstrap_requires_platform_auth(monkeypatch, tmp_path):
    monkeypatch.delenv(DEV_MODE_ENV, raising=False)
    monkeypatch.setenv(TOKEN_ENV, "correct-token")
    app = create_app(data_dir=tmp_path / "api-data")
    client = TestClient(app)
    resp = _bootstrap(client)
    assert resp.status_code == 401

    ok = client.post(
        "/gateway/organizations",
        json={
            "org_id": "acme",
            "name": "Acme Corp",
            "owner_email": "alice@acme.com",
            "owner_display_name": "Alice",
            "owner_password": "hunter2",
        },
        headers={"Authorization": "Bearer correct-token"},
    )
    assert ok.status_code == 200


def test_data_directory_can_be_configured_for_container_volume(monkeypatch, tmp_path):
    data_dir = tmp_path / "container-data"
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    monkeypatch.setenv("KARMASAKSHI_DATA_DIR", str(data_dir))

    app = create_app()
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    _bootstrap(client)

    assert (data_dir / "gateway.db").is_file()
    assert (data_dir / "tenants").is_dir()


def test_login_succeeds_with_correct_credentials(dev_client):
    _bootstrap(dev_client)
    resp = _login(dev_client)
    assert resp.status_code == 200
    body = resp.json()
    assert "session_token" in body
    assert body["user"]["email"] == "alice@acme.com"


def test_login_rejects_wrong_password(dev_client):
    _bootstrap(dev_client)
    resp = _login(dev_client, password="wrong")
    assert resp.status_code == 401


def test_login_rejects_unknown_organization(dev_client):
    resp = _login(dev_client, org_id="no-such-org")
    assert resp.status_code == 401


def test_login_does_not_require_platform_auth(monkeypatch, tmp_path):
    """Login is deliberately public -- it *is* the authentication step,
    unlike organization bootstrap which is platform-gated."""
    monkeypatch.delenv(DEV_MODE_ENV, raising=False)
    monkeypatch.setenv(TOKEN_ENV, "correct-token")
    app = create_app(data_dir=tmp_path / "api-data")
    client = TestClient(app)
    client.post(
        "/gateway/organizations",
        json={
            "org_id": "acme",
            "name": "Acme Corp",
            "owner_email": "alice@acme.com",
            "owner_display_name": "Alice",
            "owner_password": "hunter2",
        },
        headers={"Authorization": "Bearer correct-token"},
    )
    # No Authorization header at all -- login must still work.
    resp = client.post(
        "/gateway/auth/login",
        json={"org_id": "acme", "email": "alice@acme.com", "password": "hunter2"},
    )
    assert resp.status_code == 200


def test_me_returns_authenticated_user(dev_client):
    _bootstrap(dev_client)
    token = _login(dev_client).json()["session_token"]
    resp = dev_client.get("/gateway/auth/me", headers=_auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["email"] == "alice@acme.com"


def test_me_rejects_missing_authorization_header(dev_client):
    resp = dev_client.get("/gateway/auth/me")
    assert resp.status_code == 401


def test_me_rejects_malformed_authorization_header(dev_client):
    resp = dev_client.get("/gateway/auth/me", headers={"Authorization": "not-a-bearer-token"})
    assert resp.status_code == 401


def test_me_rejects_unknown_token(dev_client):
    resp = dev_client.get("/gateway/auth/me", headers=_auth_headers("bogus-token"))
    assert resp.status_code == 401


def test_get_organization_via_session(dev_client):
    _bootstrap(dev_client)
    token = _login(dev_client).json()["session_token"]
    resp = dev_client.get("/gateway/organizations/acme", headers=_auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["org_id"] == "acme"


def test_get_organization_rejects_cross_org_session(dev_client):
    _bootstrap(dev_client, org_id="acme")
    _bootstrap(dev_client, org_id="beta", owner_email="bob@beta.com", owner_password="password123")
    token = _login(dev_client, org_id="beta", email="bob@beta.com", password="password123").json()[
        "session_token"
    ]
    resp = dev_client.get("/gateway/organizations/acme", headers=_auth_headers(token))
    assert resp.status_code == 403


def test_create_and_list_organization_users(dev_client):
    _bootstrap(dev_client)
    token = _login(dev_client).json()["session_token"]
    create = dev_client.post(
        "/gateway/organizations/acme/users",
        json={
            "user_id": "u2",
            "email": "bob@acme.com",
            "display_name": "Bob",
            "password": "password123",
            "role": "member",
        },
        headers=_auth_headers(token),
    )
    assert create.status_code == 200
    assert create.json()["email"] == "bob@acme.com"

    listing = dev_client.get("/gateway/organizations/acme/users", headers=_auth_headers(token))
    assert listing.status_code == 200
    emails = {u["email"] for u in listing.json()["users"]}
    assert emails == {"alice@acme.com", "bob@acme.com"}


def test_create_duplicate_user_conflicts(dev_client):
    _bootstrap(dev_client)
    token = _login(dev_client).json()["session_token"]
    dev_client.post(
        "/gateway/organizations/acme/users",
        json={
            "user_id": "u2",
            "email": "bob@acme.com",
            "display_name": "Bob",
            "password": "password123",
        },
        headers=_auth_headers(token),
    )
    dup = dev_client.post(
        "/gateway/organizations/acme/users",
        json={
            "user_id": "u3",
            "email": "bob@acme.com",
            "display_name": "Bob Again",
            "password": "password456",
        },
        headers=_auth_headers(token),
    )
    assert dup.status_code == 409


def test_create_user_rejects_cross_org_session(dev_client):
    _bootstrap(dev_client, org_id="acme")
    _bootstrap(dev_client, org_id="beta", owner_email="bob@beta.com", owner_password="password123")
    token = _login(dev_client, org_id="beta", email="bob@beta.com", password="password123").json()[
        "session_token"
    ]
    resp = dev_client.post(
        "/gateway/organizations/acme/users",
        json={
            "user_id": "intruder",
            "email": "intruder@acme.com",
            "display_name": "Intruder",
            "password": "password123",
        },
        headers=_auth_headers(token),
    )
    assert resp.status_code == 403


def test_list_users_rejects_cross_org_session(dev_client):
    _bootstrap(dev_client, org_id="acme")
    _bootstrap(dev_client, org_id="beta", owner_email="bob@beta.com", owner_password="password123")
    token = _login(dev_client, org_id="beta", email="bob@beta.com", password="password123").json()[
        "session_token"
    ]
    resp = dev_client.get("/gateway/organizations/acme/users", headers=_auth_headers(token))
    assert resp.status_code == 403


def test_register_and_list_agents_and_adapters(dev_client):
    _bootstrap(dev_client)
    token = _login(dev_client).json()["session_token"]
    headers = _auth_headers(token)

    agent = dev_client.post(
        "/gateway/organizations/acme/agents",
        json={"agent_id": "refund-agent-1", "display_name": "Refund Agent"},
        headers=headers,
    )
    assert agent.status_code == 200
    assert agent.json()["org_id"] == "acme"
    assert dev_client.get("/gateway/organizations/acme/agents", headers=headers).json()[
        "agents"
    ] == [agent.json()]

    adapter = dev_client.post(
        "/gateway/organizations/acme/adapters",
        json={"adapter_id": "payment.simulator", "adapter_version": "1.0.0"},
        headers=headers,
    )
    assert adapter.status_code == 200
    assert adapter.json()["effect_types"] == ["payment.transfer"]
    assert dev_client.get("/gateway/organizations/acme/adapters", headers=headers).json()[
        "adapters"
    ] == [adapter.json()]


def test_resource_inventory_rejects_cross_organization_session(dev_client):
    _bootstrap(dev_client, org_id="acme")
    _bootstrap(
        dev_client,
        org_id="beta",
        owner_email="bob@beta.com",
        owner_password="password123",
    )
    token = _login(
        dev_client,
        org_id="beta",
        email="bob@beta.com",
        password="password123",
    ).json()["session_token"]
    headers = _auth_headers(token)

    assert (
        dev_client.post(
            "/gateway/organizations/acme/agents",
            json={"agent_id": "intruder", "display_name": "Intruder"},
            headers=headers,
        ).status_code
        == 403
    )
    assert (
        dev_client.get("/gateway/organizations/acme/adapters", headers=headers).status_code == 403
    )


def test_adapter_registration_rejects_unknown_id_and_version(dev_client):
    _bootstrap(dev_client)
    headers = _auth_headers(_login(dev_client).json()["session_token"])

    unknown = dev_client.post(
        "/gateway/organizations/acme/adapters",
        json={"adapter_id": "payment.fake", "adapter_version": "1.0.0"},
        headers=headers,
    )
    assert unknown.status_code == 404

    wrong_version = dev_client.post(
        "/gateway/organizations/acme/adapters",
        json={"adapter_id": "payment.simulator", "adapter_version": "9.9.9"},
        headers=headers,
    )
    assert wrong_version.status_code == 409


def test_expired_session_is_rejected(monkeypatch, tmp_path):
    from datetime import timedelta

    from karmasakshi.config.clock import SYSTEM_CLOCK, FixedClock
    from karmasakshi.gateway.api import GatewayApiState
    from karmasakshi.gateway.sessions import GatewaySessionStore
    from karmasakshi.gateway.store import GatewayStore

    monkeypatch.setenv(DEV_MODE_ENV, "1")
    clock = FixedClock(SYSTEM_CLOCK.now())
    gateway_state = GatewayApiState(
        store=GatewayStore(tmp_path / "gateway.db"),
        sessions=GatewaySessionStore(ttl=timedelta(seconds=1), clock=clock),
    )
    app = create_app(data_dir=tmp_path / "api-data", gateway_state=gateway_state)
    client = TestClient(app)
    _bootstrap(client)
    token = _login(client).json()["session_token"]

    clock.advance(timedelta(seconds=2))
    resp = client.get("/gateway/auth/me", headers=_auth_headers(token))
    assert resp.status_code == 401


def test_list_users_fails_closed_if_organization_suspended_after_session_issued(
    monkeypatch, tmp_path
):
    from karmasakshi.gateway.api import GatewayApiState
    from karmasakshi.gateway.models import OrganizationStatus
    from karmasakshi.gateway.store import GatewayStore

    monkeypatch.setenv(DEV_MODE_ENV, "1")
    store = GatewayStore(tmp_path / "gateway.db")
    gateway_state = GatewayApiState(store=store)
    app = create_app(data_dir=tmp_path / "api-data", gateway_state=gateway_state)
    client = TestClient(app)
    _bootstrap(client)
    token = _login(client).json()["session_token"]

    store.set_organization_status("acme", OrganizationStatus.SUSPENDED)

    resp = client.get("/gateway/organizations/acme/users", headers=_auth_headers(token))
    assert resp.status_code == 403


def test_create_user_fails_closed_if_organization_suspended_after_session_issued(
    monkeypatch, tmp_path
):
    from karmasakshi.gateway.api import GatewayApiState
    from karmasakshi.gateway.models import OrganizationStatus
    from karmasakshi.gateway.store import GatewayStore

    monkeypatch.setenv(DEV_MODE_ENV, "1")
    store = GatewayStore(tmp_path / "gateway.db")
    gateway_state = GatewayApiState(store=store)
    app = create_app(data_dir=tmp_path / "api-data", gateway_state=gateway_state)
    client = TestClient(app)
    _bootstrap(client)
    token = _login(client).json()["session_token"]

    store.set_organization_status("acme", OrganizationStatus.SUSPENDED)

    resp = client.post(
        "/gateway/organizations/acme/users",
        json={
            "user_id": "u2",
            "email": "bob@acme.com",
            "display_name": "Bob",
            "password": "password123",
        },
        headers=_auth_headers(token),
    )
    assert resp.status_code == 403
