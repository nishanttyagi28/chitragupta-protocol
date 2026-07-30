"""Buyer-facing Milestone A acceptance command against a real HTTP server."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")
pytest.importorskip("httpx")
pytest.importorskip("uvicorn")

import uvicorn

from karmasakshi.acceptance import run_acceptance
from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def acceptance_server(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[str]:
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    app = create_app(data_dir=tmp_path / "api-data")
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
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


def test_real_buyer_acceptance_journey(
    acceptance_server: str,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "milestone-a-acceptance.json"

    report = run_acceptance(
        base_url=acceptance_server,
        platform_token=None,
        org_id="buyer-evaluation",
        owner_email="owner@buyer-evaluation.example",
        owner_password="local-evaluation-password",
        report_path=report_path,
    )

    result = json.loads(report_path.read_text(encoding="utf-8"))
    names = {check.name for check in report.checks}
    assert report.error is None
    assert len(report.checks) >= 20
    assert result["format"] == "karmasakshi.milestone_a_acceptance.v1"
    assert result["passed"] is True
    assert {
        "Risk and exact effect displayed",
        "Modified amount or recipient rejected",
        "Ambiguous timeout recovered honestly",
        "Offline passport and audit verification successful",
        "Cross-tenant access rejected",
    } <= names
    # RA-007: the Passport itself is a deterministic content hash, not a
    # separately signed credential -- the check label must never claim
    # otherwise again.
    assert "Action Passport generated (seal/grant/audit signatures verified)" in names
    assert not any("signed action passport" in name.lower() for name in names)
