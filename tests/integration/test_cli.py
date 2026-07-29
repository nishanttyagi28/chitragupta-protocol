"""CLI tests using Typer's CliRunner against an isolated per-test workspace."""

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


def test_init_creates_workspace(workspace_args, tmp_path):
    result = _run(workspace_args + ["init"])
    assert (tmp_path / "ws").exists()
    assert (tmp_path / "ws" / "keys").exists()
    assert "Initialized" in result.output


def test_version_prints_semver():
    result = _run(["version"])
    assert result.output.strip() == "0.1.0"


def test_key_generate_and_list(workspace_args):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer-1"])
    result = _run(workspace_args + ["--json", "key", "list"])
    data = json.loads(result.output)
    assert data["key_ids"] == ["issuer-1"]


def test_key_generate_duplicate_fails(workspace_args):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer-1"])
    result = runner.invoke(app, workspace_args + ["key", "generate", "issuer-1"])
    assert result.exit_code != 0


def test_doctor_reports_failure_before_init(workspace_args):
    result = runner.invoke(app, workspace_args + ["doctor"])
    assert result.exit_code != 0
    assert "workspace" in result.output.lower() or "FAIL" in result.output


def test_doctor_passes_after_setup(workspace_args):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer-1"])
    result = _run(workspace_args + ["doctor"])
    assert "OK" in result.output


def test_full_sqlite_lifecycle_via_cli(workspace_args, tmp_path):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer-1"])
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
            "acct-1",
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
            "idem-cli-test-1",
        ]
    )
    manifest_id = json.loads(prepare_result.output)["manifest_id"]

    seal_result = _run(workspace_args + ["--json", "seal", manifest_id, "--key-id", "issuer-1"])
    assert json.loads(seal_result.output)["manifest_hash"].startswith("sha256:")

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
            "issuer-1",
            "--audience",
            "sqlite.row",
        ]
    )
    grant_id = json.loads(grant_result.output)["grant_id"]

    _run(workspace_args + ["grant", "verify", grant_id])

    execute_result = _run(
        workspace_args
        + [
            "--json",
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
    assert json.loads(execute_result.output)["success"] is True

    verify_result = _run(
        workspace_args
        + ["--json", "verify", manifest_id, "--adapter", "sqlite", "--sqlite-db-path", db_path]
    )
    assert json.loads(verify_result.output)["matched_expected"] is True

    compensate_result = _run(
        workspace_args
        + ["--json", "compensate", manifest_id, "--adapter", "sqlite", "--sqlite-db-path", db_path]
    )
    assert json.loads(compensate_result.output)["succeeded"] is True

    passport_result = _run(workspace_args + ["passport", manifest_id, "--grant-id", grant_id])
    assert manifest_id in passport_result.output
    assert "not a security certification" in passport_result.output

    audit_show_result = _run(workspace_args + ["audit", "show", manifest_id])
    assert "manifest.prepared" in audit_show_result.output
    assert "effect.committed" in audit_show_result.output

    audit_verify_result = _run(workspace_args + ["audit", "verify"])
    assert "verified" in audit_verify_result.output.lower()

    # single-use grant cannot execute twice
    second_execute = runner.invoke(
        app,
        workspace_args
        + [
            "--json",
            "execute",
            manifest_id,
            "--grant-id",
            grant_id,
            "--adapter",
            "sqlite",
            "--sqlite-db-path",
            db_path,
        ],
    )
    assert second_execute.exit_code != 0


def test_grant_revoke_blocks_future_execute(workspace_args, tmp_path):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer-1"])
    db_path = str(tmp_path / "ledger2.db")

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
            "acct-2",
            "--new-balance",
            "500",
            "--actor-id",
            "agent-1",
            "--principal-id",
            "user-1",
            "--idempotency-key",
            "idem-cli-revoke-1",
        ]
    )
    manifest_id = json.loads(prepare_result.output)["manifest_id"]
    _run(workspace_args + ["seal", manifest_id, "--key-id", "issuer-1"])
    grant_result = _run(
        workspace_args
        + [
            "--json",
            "grant",
            "issue",
            manifest_id,
            "--issuer-id",
            "approver-1",
            "--subject-id",
            "agent-1",
            "--key-id",
            "issuer-1",
            "--audience",
            "sqlite.row",
        ]
    )
    grant_id = json.loads(grant_result.output)["grant_id"]

    revoke_result = _run(
        workspace_args + ["--json", "grant", "revoke", grant_id, "--manifest-id", manifest_id]
    )
    assert json.loads(revoke_result.output)["stopped_at_safepoint"] is True

    execute_result = runner.invoke(
        app,
        workspace_args
        + [
            "--json",
            "execute",
            manifest_id,
            "--grant-id",
            grant_id,
            "--adapter",
            "sqlite",
            "--sqlite-db-path",
            db_path,
        ],
    )
    assert execute_result.exit_code != 0


def test_delegation_widening_rejected_via_cli(workspace_args):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer-1"])

    prepare_result = _run(
        workspace_args
        + [
            "--json",
            "prepare",
            "--adapter",
            "payment",
            "--source-account",
            "acct-src",
            "--beneficiary",
            "merchant-A",
            "--amount-minor-units",
            "1000",
            "--currency",
            "INR",
            "--reference",
            "inv-cli-1",
            "--fund-source-account",
            "500000",
            "--actor-id",
            "agent-1",
            "--principal-id",
            "user-1",
            "--idempotency-key",
            "idem-cli-deleg-1",
        ]
    )
    manifest_id = json.loads(prepare_result.output)["manifest_id"]
    _run(workspace_args + ["seal", manifest_id, "--key-id", "issuer-1"])
    grant_result = _run(
        workspace_args
        + [
            "--json",
            "grant",
            "issue",
            manifest_id,
            "--issuer-id",
            "approver-1",
            "--subject-id",
            "agent-1",
            "--key-id",
            "issuer-1",
            "--audience",
            "payment.simulator",
            "--max-uses",
            "5",
        ]
    )
    parent_grant_id = json.loads(grant_result.output)["grant_id"]

    result = runner.invoke(
        app,
        workspace_args
        + [
            "--json",
            "grant",
            "delegate",
            parent_grant_id,
            "--issuer-id",
            "approver-1",
            "--subject-id",
            "sub-agent-1",
            "--key-id",
            "issuer-1",
            "--max-uses",
            "10",
        ],
    )
    assert result.exit_code != 0

    narrow_result = _run(
        workspace_args
        + [
            "--json",
            "grant",
            "delegate",
            parent_grant_id,
            "--issuer-id",
            "approver-1",
            "--subject-id",
            "sub-agent-1",
            "--key-id",
            "issuer-1",
            "--max-uses",
            "1",
        ]
    )
    child_data = json.loads(narrow_result.output)
    assert child_data["parent_grant_id"] == parent_grant_id


def test_demo_all_runs_and_passes(workspace_args):
    result = _run(workspace_args + ["demo", "--all"])
    assert "15/15 scenarios behaved as expected" in result.output


def test_demo_without_all_flag_is_noop(workspace_args):
    result = _run(workspace_args + ["demo"])
    assert "--all" in result.output


def _prepare_payment_via_cli(workspace_args, idempotency_key="idem-cli-assess-1"):
    prepare_result = _run(
        workspace_args
        + [
            "--json",
            "prepare",
            "--adapter",
            "payment",
            "--source-account",
            "acct-src",
            "--beneficiary",
            "acct-dst",
            "--amount-minor-units",
            "500000",
            "--reference",
            "ref-1",
            "--actor-id",
            "agent-1",
            "--actor-type",
            "agent",
            "--principal-id",
            "user-1",
            "--principal-type",
            "human",
            "--idempotency-key",
            idempotency_key,
        ]
    )
    return json.loads(prepare_result.output)["manifest_id"]


def test_assess_reports_score_and_records_audit_event(workspace_args):
    _run(workspace_args + ["init"])
    manifest_id = _prepare_payment_via_cli(workspace_args)

    result = _run(workspace_args + ["--json", "assess", manifest_id])
    data = json.loads(result.output)
    assert 0 <= data["score"] <= 100
    assert data["recommendation"] in {"allow", "review", "block"}

    audit_result = _run(workspace_args + ["--json", "audit", "show", manifest_id])
    events = json.loads(audit_result.output)["events"]
    assert any(e["event_type"] == "effect.assessed" for e in events)


def test_assess_policy_violation_forces_block(workspace_args):
    _run(workspace_args + ["init"])
    manifest_id = _prepare_payment_via_cli(workspace_args, idempotency_key="idem-cli-assess-2")

    result = _run(
        workspace_args + ["--json", "assess", manifest_id, "--policy-violation", "sanctions_match"]
    )
    data = json.loads(result.output)
    assert data["recommendation"] == "block"


def test_assess_tri_state_flags(workspace_args):
    _run(workspace_args + ["init"])
    manifest_id = _prepare_payment_via_cli(workspace_args, idempotency_key="idem-cli-assess-3")

    result = _run(
        workspace_args
        + [
            "--json",
            "assess",
            manifest_id,
            "--provider-idempotent",
            "yes",
            "--compensation-feasible",
            "yes",
        ]
    )
    data = json.loads(result.output)
    assert "provider_idempotency_unknown" not in data["explanation"]


def test_assess_invalid_tri_state_value_rejected(workspace_args):
    _run(workspace_args + ["init"])
    manifest_id = _prepare_payment_via_cli(workspace_args, idempotency_key="idem-cli-assess-4")

    result = runner.invoke(
        app, workspace_args + ["assess", manifest_id, "--provider-idempotent", "maybe"]
    )
    assert result.exit_code != 0


def test_assess_from_audit_history_derives_recurrence(workspace_args):
    _run(workspace_args + ["init"])
    manifest_id_1 = _prepare_payment_via_cli(workspace_args, idempotency_key="idem-cli-assess-5a")
    _run(workspace_args + ["assess", manifest_id_1])

    manifest_id_2 = _prepare_payment_via_cli(workspace_args, idempotency_key="idem-cli-assess-5b")
    result = _run(workspace_args + ["--json", "assess", manifest_id_2, "--from-audit-history"])
    data = json.loads(result.output)
    assert "novel_effect_pattern_no_history" not in data["explanation"]


def test_passport_includes_assessment_section(workspace_args):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer-1"])
    manifest_id = _prepare_payment_via_cli(workspace_args, idempotency_key="idem-cli-assess-6")
    _run(workspace_args + ["assess", manifest_id])
    _run(workspace_args + ["seal", manifest_id, "--key-id", "issuer-1"])

    result = _run(workspace_args + ["passport", manifest_id])
    assert "Effect Intelligence Assessment" in result.output


# --- signed policy bundles (extreme-v2 Phase 2) -------------------------------


def test_policy_create_sign_verify_round_trip(workspace_args):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer-1"])

    create_result = _run(
        workspace_args
        + [
            "--json",
            "policy",
            "create",
            "refund-policy",
            "--issuer-id",
            "policy-admin",
            "--issuer-type",
            "human",
            "--block-threshold",
            "80",
            "--review-threshold",
            "30",
        ]
    )
    data = json.loads(create_result.output)
    assert data["bundle_id"] == "refund-policy"

    sign_result = _run(
        workspace_args + ["--json", "policy", "sign", "refund-policy", "--key-id", "issuer-1"]
    )
    assert json.loads(sign_result.output)["bundle_hash"].startswith("sha256:")

    verify_result = _run(workspace_args + ["--json", "policy", "verify", "refund-policy"])
    assert json.loads(verify_result.output)["valid"] is True


def test_policy_verify_before_sign_fails(workspace_args):
    _run(workspace_args + ["init"])
    result = runner.invoke(app, workspace_args + ["policy", "verify", "does-not-exist"])
    assert result.exit_code != 0


def test_grant_and_execute_require_matching_policy_bundle(workspace_args, tmp_path):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer-1"])
    db_path = str(tmp_path / "policy-ledger.db")

    _run(
        workspace_args
        + [
            "policy",
            "create",
            "row-policy",
            "--issuer-id",
            "policy-admin",
            "--block-threshold",
            "80",
            "--review-threshold",
            "30",
        ]
    )
    _run(workspace_args + ["policy", "sign", "row-policy", "--key-id", "issuer-1"])

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
            "acct-policy-1",
            "--new-balance",
            "1000",
            "--actor-id",
            "agent-1",
            "--principal-id",
            "user-1",
            "--idempotency-key",
            "idem-cli-policy-1",
        ]
    )
    manifest_id = json.loads(prepare_result.output)["manifest_id"]
    _run(workspace_args + ["seal", manifest_id, "--key-id", "issuer-1"])

    grant_result = _run(
        workspace_args
        + [
            "--json",
            "grant",
            "issue",
            manifest_id,
            "--issuer-id",
            "approver-1",
            "--subject-id",
            "agent-1",
            "--key-id",
            "issuer-1",
            "--audience",
            "sqlite.row",
            "--policy-bundle-id",
            "row-policy",
        ]
    )
    grant_data = json.loads(grant_result.output)
    assert grant_data["policy_bundle_hash"] is not None
    grant_id = grant_data["grant_id"]

    # Executing without the bound policy bundle must fail closed.
    missing = runner.invoke(
        app,
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
        ],
    )
    assert missing.exit_code != 0

    # Executing with the correct bundle succeeds.
    ok = _run(
        workspace_args
        + [
            "--json",
            "execute",
            manifest_id,
            "--grant-id",
            grant_id,
            "--adapter",
            "sqlite",
            "--sqlite-db-path",
            db_path,
            "--policy-bundle-id",
            "row-policy",
        ]
    )
    assert json.loads(ok.output)["success"] is True
