"""RA-001 adversarial regression: organization id must never escape the
configured tenant data root.

This is the exact class of defect the release audit reproduced: a fresh
bootstrap using an absolute Windows path as ``org_id`` returned HTTP 200 and
created database files outside the configured tenant root
(``docs/product/RELEASE_AUDIT.md``, RA-001). These tests fail against the
pre-remediation code and must keep passing afterward."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")

from fastapi.testclient import TestClient

from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV

ADVERSARIAL_ORG_IDS = [
    "C:\\evil",
    "c:/evil",
    "D:\\Windows\\System32",
    "\\\\server\\share\\evil",
    "\\\\?\\C:\\evil",
    "/etc/passwd",
    "\\etc\\passwd",
    "../../../../escape",
    "..\\..\\..\\escape",
    "org/../../escape",
    "org\\..\\..\\escape",
    "con",
    "nul",
    "prn",
    "aux",
    "com1",
    "lpt1",
    "org\x00null",
    "org\tinjected",
    "\uff43\uff4f\uff4e",  # fullwidth 'con'
    "caf\u00e9",
]


@pytest.fixture
def gateway_client(monkeypatch, tmp_path):
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    data_dir = tmp_path / "api-data"
    app = create_app(data_dir=data_dir)
    return TestClient(app), data_dir, tmp_path


def _bootstrap(client, org_id):
    return client.post(
        "/gateway/organizations",
        json={
            "org_id": org_id,
            "name": "Evil Corp",
            "owner_email": "eve@evil.example",
            "owner_display_name": "Eve",
            "owner_password": "hunter2",
        },
    )


@pytest.mark.parametrize("org_id", ADVERSARIAL_ORG_IDS)
def test_bootstrap_rejects_path_escaping_org_id(gateway_client, org_id):
    client, data_dir, root = gateway_client
    resp = _bootstrap(client, org_id)
    assert resp.status_code in (400, 422)
    # Nothing must have been created anywhere outside the configured root,
    # and the tenants directory (if it exists at all yet) must be empty.
    tenants_dir = data_dir / "tenants"
    if tenants_dir.exists():
        assert list(tenants_dir.iterdir()) == []
    # The classic RA-001 reproduction target: an absolute Windows path must
    # never be created as a sibling of the working directory or repo root.
    assert not Path("C:\\evil").exists()
    assert not (root.parent / "evil").exists()


def test_bootstrap_exact_original_repro_no_longer_escapes(gateway_client):
    """Exact reproduction from RELEASE_AUDIT.md RA-001: bootstrap with an
    absolute Windows path as org_id must not return 200 and must not create
    audit.db/grants.db/ledger.db/lifecycle.db/outbox.db outside the root."""
    client, _data_dir, _root = gateway_client
    resp = _bootstrap(client, "C:\\karmasakshi-escape-poc")
    assert resp.status_code != 200
    escaped = Path("C:\\karmasakshi-escape-poc")
    assert not escaped.exists()


def test_bootstrap_still_accepts_a_canonical_org_id(gateway_client):
    client, data_dir, _root = gateway_client
    resp = _bootstrap(client, "acme-safe")
    assert resp.status_code == 200
    assert (data_dir / "tenants" / "acme-safe").is_dir()


def test_path_param_routes_reject_escaping_org_id_even_with_a_valid_session(gateway_client):
    """A path-param org_id route (not just bootstrap) must reject a
    malformed id with 400 before any store lookup or control-plane access,
    even when the caller holds an otherwise-valid session for some org."""
    client, _data_dir, _root = gateway_client
    _bootstrap(client, "acme-safe")
    login = client.post(
        "/gateway/auth/login",
        json={"org_id": "acme-safe", "email": "eve@evil.example", "password": "hunter2"},
    )
    token = login.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}
    for org_id in ("con", "aux", "C%3A%5Cevil", "a" * 100):
        resp = client.get(f"/gateway/organizations/{org_id}", headers=headers)
        assert resp.status_code == 400
