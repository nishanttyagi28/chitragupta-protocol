"""Tests for the public sandbox demo surface (``/demo/*``).

Skipped entirely if fastapi/jinja2 are not installed (the optional ``api``
extra), matching ``tests/integration/test_api.py``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")

from fastapi.testclient import TestClient

from chitragupta.api.app import PublicDemoMisconfiguredError, create_app
from chitragupta.api.auth import DEV_MODE_ENV, PUBLIC_DEMO_ENV
from chitragupta.web import demo_state
from chitragupta.web.demo_scenarios import SCENARIO_ORDER
from chitragupta.web.rate_limit import reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_demo_singleton():
    demo_state.reset_session()
    reset_rate_limiter()
    yield
    demo_state.reset_session()
    reset_rate_limiter()


@pytest.fixture
def demo_client(monkeypatch):
    monkeypatch.setenv(PUBLIC_DEMO_ENV, "1")
    app = create_app()
    return TestClient(app, follow_redirects=False)


def test_public_demo_not_mounted_by_default():
    app = create_app()
    client = TestClient(app)
    assert client.get("/demo/").status_code == 404


def test_public_demo_and_dev_mode_together_refused(monkeypatch):
    monkeypatch.setenv(PUBLIC_DEMO_ENV, "1")
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    with pytest.raises(PublicDemoMisconfiguredError):
        create_app()


def test_health_and_ready_unaffected_by_public_demo(demo_client):
    assert demo_client.get("/health").json() == {"status": "ok"}
    assert demo_client.get("/ready").status_code == 200


def test_admin_and_docs_surfaces_stay_fail_closed(demo_client):
    # The authenticated control-plane API/console must remain unreachable without
    # CHITRAGUPTA_API_DEV_MODE or a bearer token, even while the public demo is mounted.
    assert demo_client.get("/console/").status_code == 500
    assert demo_client.get("/manifests").status_code == 500
    assert demo_client.get("/kill-switch").status_code == 500
    assert demo_client.get("/docs").status_code == 404
    assert demo_client.get("/redoc").status_code == 404
    assert demo_client.get("/openapi.json").status_code == 404


def test_landing_page_shows_sandbox_banner(demo_client):
    resp = demo_client.get("/demo/")
    assert resp.status_code == 200
    assert "Sandbox Demo" in resp.text
    for key in SCENARIO_ORDER:
        assert key in resp.text


def test_primary_refund_flow_end_to_end(demo_client):
    propose = demo_client.post("/demo/refund/propose")
    assert propose.status_code == 303
    manifest_id = propose.headers["location"].rsplit("/", 1)[-1]

    detail = demo_client.get(f"/demo/refund/{manifest_id}")
    assert detail.status_code == 200
    assert "1,500.00" in detail.text.replace("1500.00", "1,500.00") or "1500.00" in detail.text
    assert "Approve exact effect" in detail.text

    approve = demo_client.post(f"/demo/refund/{manifest_id}/approve")
    assert approve.status_code == 303

    result = demo_client.get(f"/demo/refund/{manifest_id}")
    assert result.status_code == 200
    assert "Execution result" in result.text
    assert "matched_expected=True" in result.text

    passport = demo_client.get(f"/demo/passport/{manifest_id}")
    assert passport.status_code == 200
    assert "passport" in passport.text.lower() or "Action Passport" in passport.text


def test_refund_can_be_denied(demo_client):
    propose = demo_client.post("/demo/refund/propose")
    manifest_id = propose.headers["location"].rsplit("/", 1)[-1]
    deny = demo_client.post(f"/demo/refund/{manifest_id}/deny")
    assert deny.status_code == 303
    detail = demo_client.get(f"/demo/refund/{manifest_id}")
    assert detail.status_code == 200


def test_unknown_manifest_id_shows_not_found(demo_client):
    resp = demo_client.get("/demo/refund/does-not-exist")
    assert resp.status_code == 200
    assert "Not found in this sandbox session" in resp.text


@pytest.mark.parametrize("key", SCENARIO_ORDER)
def test_each_scenario_runs_and_behaves_as_expected(demo_client, key):
    run_resp = demo_client.post(f"/demo/scenario/{key}/run")
    assert run_resp.status_code == 303
    view = demo_client.get(f"/demo/scenario/{key}")
    assert view.status_code == 200
    assert "badge-ok" in view.text, f"scenario {key} did not report an expected result"


def test_unknown_scenario_key_shows_not_found(demo_client):
    resp = demo_client.get("/demo/scenario/does-not-exist")
    assert resp.status_code == 200
    assert "Not found in this sandbox session" in resp.text


def test_audit_and_delegation_views_render(demo_client):
    demo_client.post("/demo/scenario/delegation/run")
    audit = demo_client.get("/demo/audit")
    assert audit.status_code == 200
    assert "verified" in audit.text or "TAMPERING" in audit.text
    delegation = demo_client.get("/demo/delegation")
    assert delegation.status_code == 200
    assert "delegation" in delegation.text.lower()


def test_reset_rebuilds_a_clean_session(demo_client):
    demo_client.post("/demo/refund/propose")
    before = demo_state.get_session()
    assert len(before.pending_manifests) > 0

    reset_resp = demo_client.post("/demo/reset")
    assert reset_resp.status_code == 303
    after = demo_state.get_session()
    assert after.session_id != before.session_id
    assert len(after.pending_manifests) == 0


def test_ttl_based_auto_reset(monkeypatch):
    monkeypatch.setenv(demo_state.DEMO_TTL_ENV, "60")
    demo_state.reset_session()
    first = demo_state.get_session()
    first.created_at = first.created_at.replace(year=2000)  # force it to look expired
    second = demo_state.get_session()
    assert second.session_id != first.session_id


def test_rate_limiter_blocks_after_threshold():
    from fastapi import HTTPException

    from chitragupta.web.rate_limit import RateLimiter

    limiter = RateLimiter(limit_per_minute=3)
    for _ in range(3):
        limiter.check("1.2.3.4")  # does not raise
    with pytest.raises(HTTPException) as excinfo:
        limiter.check("1.2.3.4")
    assert excinfo.value.status_code == 429
    limiter.check("5.6.7.8")  # a different client is unaffected


def test_rate_limit_returns_429_over_http(demo_client, monkeypatch):
    from chitragupta.web import rate_limit as rate_limit_module

    monkeypatch.setattr(
        rate_limit_module, "_limiter", rate_limit_module.RateLimiter(limit_per_minute=3)
    )
    codes = [demo_client.get("/demo/").status_code for _ in range(6)]
    assert codes.count(429) >= 1
