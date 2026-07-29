"""Start and seed the real Milestone A Control Center for media capture."""

from __future__ import annotations

import contextlib
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from karmasakshi.acceptance import run_acceptance
from karmasakshi.sdk import GatewayClient

HOST = "127.0.0.1"
ORG_ID = "control-center-demo"
OWNER_EMAIL = "owner@control-center-demo.invalid"
OWNER_PASSWORD = secrets.token_urlsafe(18)


@dataclass(frozen=True)
class ControlCenterDemo:
    base_url: str
    org_id: str
    owner_email: str
    owner_password: str
    pending_manifest_id: str
    verified_manifest_id: str


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def _wait_for_health(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=2) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError) as exc:
            last_error = exc
        time.sleep(0.2)
    raise RuntimeError(f"Control Center did not become healthy: {last_error}")


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        taskkill = shutil.which("taskkill")
        if taskkill is None:
            raise RuntimeError("Windows taskkill executable was not found")
        subprocess.run(
            [taskkill, "/PID", str(process.pid), "/T", "/F"],
            check=False,
            capture_output=True,
        )
        # Windows may briefly retain SQLite file handles after the process
        # tree exits; let the kernel release them before TemporaryDirectory
        # removes the seeded data directory.
        time.sleep(1)
        return
    process.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=10)
    if process.poll() is None:
        process.kill()


@contextmanager
def control_center_demo_server() -> Iterator[ControlCenterDemo]:
    """Yield a live, accepted, authentically seeded Control Center."""
    with tempfile.TemporaryDirectory(prefix="karmasakshi-control-center-") as temp:
        data_dir = Path(temp)
        port = _free_port()
        base_url = f"http://{HOST}:{port}"
        env = dict(os.environ)
        env["KARMASAKSHI_API_DEV_MODE"] = "1"
        env["KARMASAKSHI_DATA_DIR"] = str(data_dir)
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "karmasakshi.api.app:create_app",
                "--factory",
                "--host",
                HOST,
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_health(base_url)
            run_acceptance(
                base_url=base_url,
                platform_token=None,
                org_id=ORG_ID,
                owner_email=OWNER_EMAIL,
                owner_password=OWNER_PASSWORD,
                report_path=data_dir / "acceptance.json",
            )
            with GatewayClient(base_url) as client:
                client.login(
                    org_id=ORG_ID,
                    email=OWNER_EMAIL,
                    password=OWNER_PASSWORD,
                )
                verified = client.propose_refund(
                    ORG_ID,
                    agent_id="refund-agent-1",
                    requested_by="customer-verified-visual",
                    beneficiary="customer-ledger-verified-1002",
                    amount_minor_units=60_000,
                    reference="order-verified-1002",
                    idempotency_key="control-center-demo-verified-visual",
                )
                approver_credentials: list[tuple[str, str]] = []
                for index in range(1, verified.assessment.required_human_approvals):
                    email = f"media-approver-{index}@{ORG_ID}.invalid"
                    password = secrets.token_urlsafe(18)
                    client.create_user(
                        ORG_ID,
                        user_id=f"{ORG_ID}-media-approver-{index}",
                        email=email,
                        display_name=f"Media Approver {index}",
                        password=password,
                    )
                    approver_credentials.append((email, password))
                approval = client.approve_refund(ORG_ID, verified.manifest_id)
                for email, password in approver_credentials:
                    with GatewayClient(base_url) as approver:
                        approver.login(
                            org_id=ORG_ID,
                            email=email,
                            password=password,
                        )
                        approval = approver.approve_refund(
                            ORG_ID,
                            verified.manifest_id,
                        )
                if approval.grant_id is None:
                    raise RuntimeError("media refund approval quorum did not issue a grant")
                client.execute_refund(
                    ORG_ID,
                    verified.manifest_id,
                    grant_id=approval.grant_id,
                )
                client.verify_refund(ORG_ID, verified.manifest_id)
                pending = client.propose_refund(
                    ORG_ID,
                    agent_id="refund-agent-1",
                    requested_by="customer-visual-review",
                    beneficiary="customer-ledger-visual-1003",
                    amount_minor_units=75_000,
                    reference="order-visual-1003",
                    idempotency_key="control-center-demo-pending-visual",
                )
            yield ControlCenterDemo(
                base_url=base_url,
                org_id=ORG_ID,
                owner_email=OWNER_EMAIL,
                owner_password=OWNER_PASSWORD,
                pending_manifest_id=pending.manifest_id,
                verified_manifest_id=verified.manifest_id,
            )
        finally:
            _stop_process(process)


__all__ = ["ControlCenterDemo", "control_center_demo_server"]
