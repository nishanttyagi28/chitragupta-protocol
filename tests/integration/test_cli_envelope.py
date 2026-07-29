"""CLI Decision Envelope coverage (Phase 6)."""

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


def _init_with_key(workspace_args):
    _run(workspace_args + ["init"])
    _run(workspace_args + ["key", "generate", "issuer"])


def test_envelope_create_verify_substitute_round_trip(workspace_args):
    _init_with_key(workspace_args)
    created = _run(
        workspace_args
        + [
            "--json",
            "envelope",
            "create",
            "env-cli-1",
            "--effect-type",
            "payment.transfer",
            "--adapter-id",
            "payment",
            "--adapter-version",
            "1.0",
            "--target-resource",
            "payment:beneficiary/X",
            "--constraint",
            "amount=monetary:INR:1:150000",
            "--constraint",
            "currency=enum:INR,USD",
            "--constraint",
            "quantity=int:1:10",
            "--constraint",
            "recipient=exact:customer-priya",
            "--constraint",
            "flag=exact:true",
            "--constraint",
            "maybe=exact:null",
            "--constraint",
            "count=exact:7",
            "--max-cost-currency",
            "INR",
            "--max-cost-minor-units",
            "200000",
            "--ttl-seconds",
            "3600",
            "--key-id",
            "issuer",
        ]
    )
    body = json.loads(created.output)
    assert body["envelope_id"] == "env-cli-1"
    assert body["signed"] is True
    assert body["envelope_hash"].startswith("sha256:")

    verified = _run(workspace_args + ["--json", "envelope", "verify", "env-cli-1"])
    assert json.loads(verified.output)["verified"] is True

    substituted = _run(
        workspace_args
        + [
            "--json",
            "envelope",
            "substitute",
            "env-cli-1",
            "--choice",
            "amount=1500",
            "--choice",
            "currency=INR",
            "--choice",
            "quantity=3",
            "--choice",
            "flag=true",
            "--choice",
            "maybe=null",
        ]
    )
    params = json.loads(substituted.output)["parameters"]
    assert params["amount"] == 1500
    assert params["currency"] == "INR"
    assert params["quantity"] == 3
    assert params["recipient"] == "customer-priya"
    assert params["flag"] is True
    assert params["maybe"] is None
    assert params["count"] == 7


def test_envelope_create_unsigned_and_constraint_parse_errors(workspace_args):
    _init_with_key(workspace_args)
    unsigned = _run(
        workspace_args
        + [
            "--json",
            "envelope",
            "create",
            "env-unsigned",
            "--effect-type",
            "payment.transfer",
            "--adapter-id",
            "payment",
            "--target-resource",
            "payment:beneficiary/X",
            "--constraint",
            "currency=enum:INR",
            "--no-sign",
            "--key-id",
            "issuer",
        ]
    )
    assert json.loads(unsigned.output)["signed"] is False

    bad_specs = [
        "broken",
        "x=weird:1",
        "n=int:5",
        "m=monetary:INR",
        "name=exact",
    ]
    for spec in bad_specs:
        result = runner.invoke(
            app,
            workspace_args
            + [
                "envelope",
                "create",
                "bad",
                "--effect-type",
                "payment.transfer",
                "--adapter-id",
                "payment",
                "--target-resource",
                "t",
                "--constraint",
                spec,
                "--key-id",
                "issuer",
            ],
        )
        assert result.exit_code != 0

    missing_target = runner.invoke(
        app,
        workspace_args
        + [
            "envelope",
            "create",
            "no-target",
            "--effect-type",
            "payment.transfer",
            "--adapter-id",
            "payment",
            "--key-id",
            "issuer",
        ],
    )
    assert missing_target.exit_code != 0


def test_envelope_substitute_choice_parse_and_enum_null_bool(workspace_args):
    _init_with_key(workspace_args)
    _run(
        workspace_args
        + [
            "envelope",
            "create",
            "env-choices",
            "--effect-type",
            "payment.transfer",
            "--adapter-id",
            "payment",
            "--target-resource",
            "payment:beneficiary/X",
            "--constraint",
            "mode=enum:null,true,false,live",
            "--constraint",
            "n=int::100",
            "--constraint",
            "amt=monetary:INR::5000",
            "--key-id",
            "issuer",
        ]
    )
    bad_choice = runner.invoke(
        app,
        workspace_args + ["envelope", "substitute", "env-choices", "--choice", "mode"],
    )
    assert bad_choice.exit_code != 0

    ok = _run(
        workspace_args
        + [
            "--json",
            "envelope",
            "substitute",
            "env-choices",
            "--choice",
            "mode=live",
            "--choice",
            "n=42",
            "--choice",
            "amt=100",
        ]
    )
    assert json.loads(ok.output)["parameters"]["mode"] == "live"


def test_envelope_with_causal_graph_pin(workspace_args, tmp_path):
    _init_with_key(workspace_args)
    db_path = str(tmp_path / "ledger.db")

    def _prepare(idem: str) -> str:
        result = _run(
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
                f"row-{idem}",
                "--new-balance",
                "100",
                "--actor-id",
                "agent-1",
                "--actor-type",
                "agent",
                "--principal-id",
                "user-1",
                "--principal-type",
                "human",
                "--idempotency-key",
                idem,
            ]
        )
        mid = json.loads(result.output)["manifest_id"]
        _run(workspace_args + ["seal", mid, "--key-id", "issuer"])
        return mid

    parent = _prepare("graph-parent")
    child = _prepare("graph-child")
    graph = _run(
        workspace_args
        + [
            "--json",
            "graph",
            "create",
            "plan-1",
            "--manifest-id",
            parent,
            "--manifest-id",
            child,
            "--edge",
            f"{parent}:{child}:causes",
            "--key-id",
            "issuer",
        ]
    )
    assert json.loads(graph.output)["graph_hash"].startswith("sha256:")
    verified = _run(workspace_args + ["--json", "graph", "verify", "plan-1"])
    assert json.loads(verified.output)["verified"] is True

    bad_edge = runner.invoke(
        app,
        workspace_args
        + [
            "graph",
            "create",
            "bad-plan",
            "--manifest-id",
            parent,
            "--manifest-id",
            child,
            "--edge",
            "not-an-edge",
            "--key-id",
            "issuer",
        ],
    )
    assert bad_edge.exit_code != 0

    env = _run(
        workspace_args
        + [
            "--json",
            "envelope",
            "create",
            "env-with-graph",
            "--effect-type",
            "sqlite.row.insert",
            "--adapter-id",
            "sqlite.row",
            "--target-resource",
            "sqlite:accounts/row-graph-parent",
            "--constraint",
            "new_balance=int:0:1000",
            "--causal-graph-id",
            "plan-1",
            "--key-id",
            "issuer",
        ]
    )
    assert json.loads(env.output)["signed"] is True
