from __future__ import annotations

from typing import Annotated

import typer

from karmasakshi.cli.adapter_factory import build_adapter
from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace


def execute(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    grant_id: Annotated[str, typer.Option()],
    adapter: Annotated[str, typer.Option("--adapter", help="sqlite, email, or payment")],
    sqlite_db_path: Annotated[str | None, typer.Option()] = None,
    sqlite_table: Annotated[str, typer.Option()] = "ledger_accounts",
    fund_source_account: Annotated[int | None, typer.Option()] = None,
    fund_account_id: Annotated[str, typer.Option()] = "acct-src",
    policy_bundle_id: Annotated[
        str | None,
        typer.Option(
            "--policy-bundle-id",
            help="Required if the grant was issued with a policy bundle bound to it; "
            "must be the same bundle (by hash) presented at `grant issue` time",
        ),
    ] = None,
    decision_envelope_id: Annotated[
        str | None,
        typer.Option(
            "--decision-envelope-id",
            help="Required if the grant was issued with a Decision Envelope bound; "
            "must be the same envelope (by hash) presented at `grant issue` time",
        ),
    ] = None,
    causal_graph_id: Annotated[
        str | None,
        typer.Option(
            "--causal-graph-id",
            help="Required if the grant was issued via atomic plan authorization; "
            "must be the same graph (by hash) presented at `grant issue` time",
        ),
    ] = None,
) -> None:
    """Commit a sealed, authorized manifest through its adapter."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        sealed = workspace.load_sealed_manifest(manifest_id)
        grant = workspace.load_grant(grant_id)
        adapter_instance = build_adapter(
            adapter,
            sqlite_db_path=sqlite_db_path,
            sqlite_table=sqlite_table,
            fund_source_account=fund_source_account,
            fund_account_id=fund_account_id,
        )
        engine = workspace.build_engine()
        workspace.reconstruct_lifecycle_state(engine, manifest_id)
        policy_bundle = (
            workspace.load_sealed_policy_bundle(policy_bundle_id)
            if policy_bundle_id is not None
            else None
        )
        decision_envelope = (
            workspace.load_decision_envelope(decision_envelope_id)
            if decision_envelope_id is not None
            else None
        )
        causal_graph = (
            workspace.load_causal_graph(causal_graph_id) if causal_graph_id is not None else None
        )
        result = engine.commit(
            sealed,
            grant,
            adapter_instance,
            context=None,
            policy_bundle=policy_bundle,
            decision_envelope=decision_envelope,
            causal_graph=causal_graph,
        )
        workspace.save_commit_result(manifest_id, result)
        emit(
            {
                "manifest_id": manifest_id,
                "success": result.success,
                "provider_reference": result.provider_reference,
                "detail": result.detail,
            },
            as_json=as_json,
            human=(
                f"Commit {'succeeded' if result.success else 'failed'} for "
                f"[bold]{manifest_id}[/bold]: {result.detail or result.provider_reference or ''}"
            ),
        )

    run_guarded(as_json, _do)


def verify(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    adapter: Annotated[str, typer.Option("--adapter", help="sqlite, email, or payment")],
    sqlite_db_path: Annotated[str | None, typer.Option()] = None,
    sqlite_table: Annotated[str, typer.Option()] = "ledger_accounts",
) -> None:
    """Independently verify the observed outcome of a committed manifest."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        sealed = workspace.load_sealed_manifest(manifest_id)
        commit_result = workspace.load_commit_result(manifest_id)
        if commit_result is None:
            raise ValueError(
                f"no commit result found for manifest_id={manifest_id!r}; run execute first"
            )
        adapter_instance = build_adapter(
            adapter,
            sqlite_db_path=sqlite_db_path,
            sqlite_table=sqlite_table,
            fund_source_account=None,
            fund_account_id="acct-src",
        )
        engine = workspace.build_engine()
        workspace.reconstruct_lifecycle_state(engine, manifest_id)
        proof = engine.verify(sealed.manifest, commit_result, adapter_instance, context=None)
        workspace.save_outcome_proof(manifest_id, proof)
        emit(
            {
                "manifest_id": manifest_id,
                "matched_expected": proof.matched_expected,
                "detail": proof.detail,
            },
            as_json=as_json,
            human=(
                f"Verification for [bold]{manifest_id}[/bold]: "
                f"{'matched expected outcome' if proof.matched_expected else 'MISMATCH'}"
            ),
        )

    run_guarded(as_json, _do)


def compensate(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    adapter: Annotated[str, typer.Option("--adapter", help="sqlite, email, or payment")],
    sqlite_db_path: Annotated[str | None, typer.Option()] = None,
    sqlite_table: Annotated[str, typer.Option()] = "ledger_accounts",
) -> None:
    """Attempt best-effort compensation of a committed manifest."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        sealed = workspace.load_sealed_manifest(manifest_id)
        commit_result = workspace.load_commit_result(manifest_id)
        if commit_result is None:
            raise ValueError(
                f"no commit result found for manifest_id={manifest_id!r}; run execute first"
            )
        adapter_instance = build_adapter(
            adapter,
            sqlite_db_path=sqlite_db_path,
            sqlite_table=sqlite_table,
            fund_source_account=None,
            fund_account_id="acct-src",
        )
        engine = workspace.build_engine()
        workspace.reconstruct_lifecycle_state(engine, manifest_id)
        result = engine.compensate(sealed.manifest, commit_result, adapter_instance, context=None)
        workspace.save_compensation_result(manifest_id, result)
        emit(
            {
                "manifest_id": manifest_id,
                "attempted": result.attempted,
                "succeeded": result.succeeded,
                "reason": result.reason,
            },
            as_json=as_json,
            human=(
                f"Compensation for [bold]{manifest_id}[/bold]: "
                f"attempted={result.attempted}, succeeded={result.succeeded}"
                + (f" ({result.reason})" if result.reason else "")
            ),
        )

    run_guarded(as_json, _do)


__all__ = ["compensate", "execute", "verify"]
