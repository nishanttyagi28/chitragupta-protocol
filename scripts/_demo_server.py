"""Shared helper: start/stop a local uvicorn instance of the public demo for
``scripts/capture_screenshots.py`` and ``scripts/record_demo.py``.

Runs the exact same ``chitragupta.api.app:create_app`` factory used by the
Dockerfile and ``render.yaml`` public deployment, with
``CHITRAGUPTA_PUBLIC_DEMO=1`` -- these scripts drive the real application,
not a mock or a hand-built animation.
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager

HOST = "127.0.0.1"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def _wait_for_health(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=2) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError) as exc:
            last_error = exc
        time.sleep(0.3)
    raise RuntimeError(f"demo server did not become healthy in {timeout}s: {last_error}")


@contextmanager
def demo_server(ttl_seconds: int = 3600, rate_limit_per_minute: int = 10_000) -> Iterator[str]:
    """Start the public demo app in a subprocess; yield its base URL."""
    port = _free_port()
    env = dict(os.environ)
    env["CHITRAGUPTA_PUBLIC_DEMO"] = "1"
    env["CHITRAGUPTA_DEMO_TTL_SECONDS"] = str(ttl_seconds)
    env["CHITRAGUPTA_DEMO_RATE_LIMIT_PER_MINUTE"] = str(rate_limit_per_minute)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "chitragupta.api.app:create_app",
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
    base_url = f"http://{HOST}:{port}"
    try:
        _wait_for_health(base_url)
        yield base_url
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)
        if proc.poll() is None:
            proc.kill()


__all__ = ["demo_server"]
