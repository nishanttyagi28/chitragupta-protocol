"""Real Control Center integration and browser-security tests."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("jinja2")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from karmasakshi.adapters.payment_simulator import PaymentSimulatorAdapter
from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV

_SESSION_COOKIE = "karmasakshi_cc_session"


@pytest.fixture
def control_center(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[TestClient, FastAPI]:
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    app = create_app(data_dir=tmp_path / "api-data")
    return TestClient(app, follow_redirects=False), app


def _bootstrap(
    client: TestClient,
    *,
    org_id: str = "acme",
    email: str = "alice@acme.com",
    password: str = "hunter2",
) -> None:
    response = client.post(
        "/gateway/organizations",
        json={
            "org_id": org_id,
            "name": f"{org_id.title()} Corp",
            "owner_email": email,
            "owner_display_name": email.split("@", 1)[0].title(),
            "owner_password": password,
        },
    )
    assert response.status_code == 200


def _api_login(
    client: TestClient,
    *,
    org_id: str = "acme",
    email: str = "alice@acme.com",
    password: str = "hunter2",
) -> str:
    response = client.post(
        "/gateway/auth/login",
        json={"org_id": org_id, "email": email, "password": password},
    )
    assert response.status_code == 200
    return str(response.json()["session_token"])


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _hidden_csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _ui_login(
    client: TestClient,
    *,
    org_id: str = "acme",
    email: str = "alice@acme.com",
    password: str = "hunter2",
) -> str:
    page = client.get("/control-center/login")
    assert page.status_code == 200
    csrf = _hidden_csrf(page.text)
    response = client.post(
        "/control-center/login",
        data={
            "org_id": org_id,
            "email": email,
            "password": password,
            "csrf_token": csrf,
        },
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/control-center/"
    token = client.cookies.get(_SESSION_COOKIE)
    assert token is not None
    return cast(str, token)


def _propose(
    client: TestClient,
    token: str,
    *,
    org_id: str = "acme",
    reference: str = "order-1001",
    amount: int = 50_000,
    beneficiary: str = "customer-acct-1",
) -> dict[str, Any]:
    response = client.post(
        f"/gateway/organizations/{org_id}/refunds/propose",
        json={
            "agent_id": "refund-agent-1",
            "requested_by": "customer-1",
            "beneficiary": beneficiary,
            "amount_minor_units": amount,
            "reference": reference,
            "idempotency_key": f"idem-{reference}",
        },
        headers=_headers(token),
    )
    assert response.status_code == 200
    return cast(dict[str, Any], response.json())


def test_login_uses_safe_cookie_and_protected_pages_fail_closed(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    protected = client.get("/control-center/")
    assert protected.status_code == 303
    assert protected.headers["location"] == "/control-center/login"

    _bootstrap(client)
    token = _ui_login(client)
    login_cookie = client.cookies.get(_SESSION_COOKIE)
    assert login_cookie == token

    # The credential is an HttpOnly cookie, never rendered into page content.
    set_cookie = client.post(
        "/control-center/logout",
        data={"csrf_token": "invalid"},
    ).request.headers.get("cookie", "")
    assert token in set_cookie
    fresh_login = client.get("/control-center/")
    assert fresh_login.status_code == 200
    assert token not in fresh_login.text
    assert fresh_login.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in fresh_login.headers["content-security-policy"]
    assert fresh_login.headers["x-content-type-options"] == "nosniff"


def test_login_response_sets_httponly_strict_cookie(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    _bootstrap(client)
    page = client.get("/control-center/login")
    response = client.post(
        "/control-center/login",
        data={
            "org_id": "acme",
            "email": "alice@acme.com",
            "password": "hunter2",
            "csrf_token": _hidden_csrf(page.text),
        },
    )
    cookie_header = response.headers["set-cookie"]
    assert "HttpOnly" in cookie_header
    assert "SameSite=strict" in cookie_header
    assert "Path=/control-center" in cookie_header
    assert "karmasakshi_cc_session=" in cookie_header


def test_dashboard_inbox_and_detail_render_real_gateway_read_models(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    _bootstrap(client)
    token = _ui_login(client)
    policy = client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "refund-policy-v1"},
        headers=_headers(token),
    )
    assert policy.status_code == 200
    proposal = _propose(client, token)
    manifest_id = proposal["manifest_id"]

    overview = client.get("/control-center/")
    assert overview.status_code == 200
    assert "order-1001" in overview.text
    assert "Pending decisions" in overview.text

    inbox = client.get("/control-center/approvals")
    assert inbox.status_code == 200
    assert manifest_id in inbox.text
    assert "Review exact effect" in inbox.text

    detail = client.get(f"/control-center/refunds/{manifest_id}")
    assert detail.status_code == 200
    assert "Exact before and after" in detail.text
    assert "100000.00" in detail.text
    assert "99500.00" in detail.text
    assert "+ INR 500.00" in detail.text
    assert "Risk assessment" in detail.text
    assert "Policy decision" in detail.text
    assert "refund-policy-v1" in detail.text

    read_model = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}",
        headers=_headers(token),
    ).json()
    assert read_model["effect"]["source_balance_before_minor_units"] == 10_000_000
    assert read_model["effect"]["source_balance_expected_after_minor_units"] == 9_950_000
    assert read_model["assessment"]["signals"]
    assert read_model["policy_decision"]["required_human_approvals"] >= 1


def test_approve_execute_verify_and_passport_use_real_lifecycle(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    _bootstrap(client)
    token = _ui_login(client)
    proposal = _propose(client, token)
    manifest_id = proposal["manifest_id"]
    csrf = _hidden_csrf(client.get(f"/control-center/refunds/{manifest_id}").text)

    approved = client.post(
        f"/control-center/refunds/{manifest_id}/approve",
        data={"csrf_token": csrf},
    )
    assert approved.status_code == 303
    detail = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}",
        headers=_headers(token),
    ).json()
    assert detail["authorized_by"] == "acme-owner"
    assert detail["policy_decision"]["completed_human_approvals"] == 1

    executed = client.post(
        f"/control-center/refunds/{manifest_id}/execute",
        data={"csrf_token": csrf},
    )
    assert executed.status_code == 303
    verified = client.post(
        f"/control-center/refunds/{manifest_id}/verify",
        data={"csrf_token": csrf},
    )
    assert verified.status_code == 303

    final_detail = client.get(f"/control-center/refunds/{manifest_id}")
    assert "verified match" in final_detail.text
    assert "provider status: settled" in final_detail.text
    passport = client.get(f"/control-center/refunds/{manifest_id}/passport")
    assert passport.status_code == 200
    assert "Action Passport" in passport.text
    assert "verified_match" in passport.text
    assert "action_passport.v2" in passport.text


def test_deny_records_authenticated_actor_and_blocks_later_approval(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    _bootstrap(client)
    token = _ui_login(client)
    manifest_id = _propose(client, token)["manifest_id"]
    csrf = _hidden_csrf(client.get(f"/control-center/refunds/{manifest_id}").text)

    denied = client.post(
        f"/control-center/refunds/{manifest_id}/deny",
        data={"csrf_token": csrf, "reason": "Customer already received a refund."},
    )
    assert denied.status_code == 303
    blocked = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/approve",
        json={},
        headers=_headers(token),
    )
    assert blocked.status_code == 409

    detail = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}",
        headers=_headers(token),
    ).json()
    assert detail["decision_status"] == "denied"
    assert detail["denied_by"] == "acme-owner"
    assert detail["denial_reason"] == "Customer already received a refund."
    assert detail["can_approve"] is False
    inbox = client.get("/control-center/approvals")
    assert manifest_id not in inbox.text


def test_mutating_actions_require_valid_csrf(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    _bootstrap(client)
    token = _ui_login(client)
    manifest_id = _propose(client, token)["manifest_id"]

    missing = client.post(f"/control-center/refunds/{manifest_id}/approve")
    assert missing.status_code == 403
    assert "security token was missing or invalid" in missing.text
    invalid = client.post(
        f"/control-center/refunds/{manifest_id}/approve",
        data={"csrf_token": "attacker-controlled"},
    )
    assert invalid.status_code == 403
    read_model = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}",
        headers=_headers(token),
    ).json()
    assert read_model["decision_status"] == "pending"
    assert read_model["grant_id"] is None


def test_control_center_never_accepts_browser_tenant_scope(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    _bootstrap(client)
    _bootstrap(
        client,
        org_id="beta",
        email="bob@beta.com",
        password="password123",
    )
    beta_token = _api_login(
        client,
        org_id="beta",
        email="bob@beta.com",
        password="password123",
    )
    beta_manifest = _propose(
        client,
        beta_token,
        org_id="beta",
        reference="beta-secret-order",
        beneficiary="beta-secret-beneficiary",
    )["manifest_id"]

    _ui_login(client)
    not_found = client.get(f"/control-center/refunds/{beta_manifest}")
    assert not_found.status_code == 404
    assert "beta-secret" not in not_found.text
    audit = client.get(f"/control-center/audit?q={beta_manifest}")
    assert audit.status_code == 200
    assert "No audit events matched" in audit.text


def test_audit_explorer_searches_real_org_scoped_events(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    _bootstrap(client)
    token = _ui_login(client)
    manifest_id = _propose(client, token)["manifest_id"]

    by_manifest = client.get(f"/control-center/audit?q={manifest_id}")
    assert by_manifest.status_code == 200
    assert manifest_id[:12] in by_manifest.text
    assert "manifest.prepared" in by_manifest.text
    exact = client.get("/control-center/audit?event_type=manifest.sealed&decision=allowed")
    assert exact.status_code == 200
    assert "manifest.sealed" in exact.text
    assert "Chain verified" in exact.text


def test_ambiguous_outcome_is_visible_then_recovered_by_observation(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, app = control_center
    _bootstrap(client)
    token = _ui_login(client)
    manifest_id = _propose(client, token)["manifest_id"]
    approved = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/approve",
        json={},
        headers=_headers(token),
    )
    assert approved.status_code == 200

    state = app.state.karmasakshi_gateway.control_plane.get_state("acme")
    adapter = state.adapters["payment.simulator"]
    assert isinstance(adapter, PaymentSimulatorAdapter)
    adapter.simulator.inject_ambiguous_timeout()

    csrf = _hidden_csrf(client.get(f"/control-center/refunds/{manifest_id}").text)
    executed = client.post(
        f"/control-center/refunds/{manifest_id}/execute",
        data={"csrf_token": csrf},
    )
    assert executed.status_code == 303
    ambiguous = client.get(f"/control-center/refunds/{manifest_id}")
    assert "ambiguous" in ambiguous.text
    assert "Recover by observation" in ambiguous.text

    recovered = client.post(
        f"/control-center/refunds/{manifest_id}/recover",
        data={"csrf_token": csrf},
    )
    assert recovered.status_code == 303
    final = client.get(f"/control-center/refunds/{manifest_id}")
    assert "verified match" in final.text
    assert "Recover by observation" not in final.text


def test_logout_revokes_server_session_and_clears_browser_cookie(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    _bootstrap(client)
    token = _ui_login(client)
    csrf = _hidden_csrf(client.get("/control-center/").text)
    response = client.post("/control-center/logout", data={"csrf_token": csrf})
    assert response.status_code == 303
    assert client.cookies.get(_SESSION_COOKIE) is None
    rejected = client.get("/gateway/auth/me", headers=_headers(token))
    assert rejected.status_code == 401


def test_tampered_session_cookie_is_evicted_without_detail(
    control_center: tuple[TestClient, FastAPI],
) -> None:
    client, _app = control_center
    client.cookies.set(_SESSION_COOKIE, "tampered", path="/control-center")
    response = client.get("/control-center/")
    assert response.status_code == 303
    assert response.headers["location"] == "/control-center/login"
    assert "invalid" not in response.text.casefold()
