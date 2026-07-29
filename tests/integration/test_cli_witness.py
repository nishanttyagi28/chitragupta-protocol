"""CLI integration for witness commands."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from karmasakshi.cli.app import app

runner = CliRunner()


@pytest.fixture
def workspace_args(tmp_path):
    return ["--workspace", str(tmp_path / "ws")]


def _run(args, expect_ok=True):
    result = runner.invoke(app, args)
    if expect_ok and result.exit_code != 0:
        raise AssertionError(
            f"CLI failed ({result.exit_code}): {result.output}\n{result.exception}"
        )
    return result


def test_cli_witness_sign_and_evaluate(workspace_args):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer"])
    _run(workspace_args + ["key", "generate", "witness-alice"])

    prep = _run(
        workspace_args
        + [
            "--json",
            "prepare",
            "--adapter",
            "payment",
            "--actor-id",
            "agent-1",
            "--principal-id",
            "user-1",
            "--idempotency-key",
            "idem-cli-witness-1",
            "--source-account",
            "acct-src",
            "--beneficiary",
            "merchant-A",
            "--amount-minor-units",
            "1000",
            "--currency",
            "INR",
            "--reference",
            "idem-cli-witness-1",
            "--fund-source-account",
            "100000",
        ]
    )
    mid = json.loads(prep.output)["manifest_id"]
    _run(workspace_args + ["seal", mid, "--key-id", "issuer"])

    signed = _run(
        workspace_args
        + [
            "--json",
            "witness",
            "sign",
            mid,
            "--witness-id",
            "alice",
            "--key-id",
            "witness-alice",
            "--observed-digest",
            "digest-cli-1",
            "--required-witnesses",
            "1",
        ]
    )
    assert json.loads(signed.output)["signature"]

    evaluated = _run(
        workspace_args
        + [
            "--json",
            "witness",
            "evaluate",
            mid,
            "--observed-digest",
            "digest-cli-1",
            "--actor-id",
            "agent-1",
            "--subject-id",
            "exec-1",
            "--required-witnesses",
            "1",
            "--assert",
        ]
    )
    payload = json.loads(evaluated.output)
    assert payload["satisfied"] is True
    assert payload["witness_set_hash"]
