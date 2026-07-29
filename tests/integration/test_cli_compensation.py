"""CLI coverage for authorized compensation (Phase 7)."""

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


def test_cli_authorized_compensation_sqlite(workspace_args, tmp_path):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer"])
    db_path = str(tmp_path / "ledger.db")

    prepare_result = _run(
        workspace_args
        + [
            "--json",
            "prepare",
            "--adapter",
            "sqlite",
            "--sqlite-db-path",
            db_path,
            "--row-operation",
            "insert",
            "--row-id",
            "acct-comp",
            "--new-balance",
            "1000",
            "--actor-id",
            "agent-1",
            "--actor-type",
            "agent",
            "--principal-id",
            "user-1",
            "--principal-type",
            "human",
            "--idempotency-key",
            "idem-comp-cli-1",
        ]
    )
    manifest_id = json.loads(prepare_result.output)["manifest_id"]
    _run(workspace_args + ["seal", manifest_id, "--key-id", "issuer"])
    grant_result = _run(
        workspace_args
        + [
            "--json",
            "grant",
            "issue",
            manifest_id,
            "--issuer-id",
            "approver-1",
            "--issuer-type",
            "human",
            "--subject-id",
            "agent-1",
            "--subject-type",
            "agent",
            "--key-id",
            "issuer",
            "--audience",
            "sqlite.row",
        ]
    )
    grant_id = json.loads(grant_result.output)["grant_id"]
    _run(
        workspace_args
        + [
            "execute",
            manifest_id,
            "--grant-id",
            grant_id,
            "--adapter",
            "sqlite",
            "--sqlite-db-path",
            db_path,
        ]
    )
    _run(
        workspace_args + ["verify", manifest_id, "--adapter", "sqlite", "--sqlite-db-path", db_path]
    )

    comp_prep = _run(
        workspace_args + ["--json", "compensation", "prepare", manifest_id, "--key-id", "issuer"]
    )
    compensation_id = json.loads(comp_prep.output)["compensation_manifest_id"]

    comp_auth = _run(
        workspace_args
        + [
            "--json",
            "compensation",
            "authorize",
            manifest_id,
            compensation_id,
            "--key-id",
            "issuer",
            "--audience",
            "sqlite.row",
        ]
    )
    comp_grant = json.loads(comp_auth.output)["grant_id"]

    comp_exec = _run(
        workspace_args
        + [
            "--json",
            "compensation",
            "execute",
            manifest_id,
            compensation_id,
            "--grant-id",
            comp_grant,
            "--adapter",
            "sqlite",
            "--sqlite-db-path",
            db_path,
        ]
    )
    assert "success" in json.loads(comp_exec.output)

    passport = _run(
        workspace_args
        + [
            "--json",
            "compensation",
            "passport",
            manifest_id,
            compensation_id,
            "--grant-id",
            comp_grant,
        ]
    )
    body = json.loads(passport.output)
    assert body["status"] in {"refused", "attempted", "verified"}
    assert body["original_manifest_id"] == manifest_id
