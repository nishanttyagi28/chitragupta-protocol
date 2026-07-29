from __future__ import annotations

import subprocess
import sys


def test_acceptance_help_does_not_require_optional_sdk_dependencies() -> None:
    script = """
import builtins
import runpy
import sys

real_import = builtins.__import__

def blocked_import(name, *args, **kwargs):
    if name == "httpx" or name.startswith("karmasakshi.sdk"):
        raise ModuleNotFoundError(f"blocked optional dependency: {name}")
    return real_import(name, *args, **kwargs)

builtins.__import__ = blocked_import
sys.argv = ["karmasakshi-acceptance", "--help"]
runpy.run_module("karmasakshi.acceptance", run_name="__main__")
"""
    result = subprocess.run(  # noqa: S603 - fixed interpreter and in-repository test script
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Drive the real Milestone A refund journey" in result.stdout
