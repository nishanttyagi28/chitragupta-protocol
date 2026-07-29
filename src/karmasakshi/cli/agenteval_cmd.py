"""Export a failure as an AgentEval regression fixture and record it into
the local failure-memory store (extreme-v2 Phase 25)."""

from __future__ import annotations

from typing import Annotated

import typer

from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.integrations.agenteval import (
    FailureMemoryStore,
    export_regression_fixture,
    failure_signature,
)

agenteval_app = typer.Typer(help="AgentEval regression-fixture export and failure memory.")


@agenteval_app.command("record")
def record(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    failure_category: Annotated[str, typer.Option("--failure-category")],
    invariant: Annotated[str | None, typer.Option("--invariant")] = None,
) -> None:
    """Export the manifest's outcome as a regression fixture and record it
    into this workspace's failure-memory store, reporting how many times a
    failure of this exact shape has been seen before."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        manifest = workspace.load_manifest_any(manifest_id)
        commit_result = workspace.load_commit_result(manifest_id)
        outcome_proof = workspace.load_outcome_proof(manifest_id)
        fixture = export_regression_fixture(
            manifest=manifest,
            failure_category=failure_category,
            commit_result=commit_result,
            outcome_proof=outcome_proof,
            invariant=invariant,
        )
        store = FailureMemoryStore(workspace.agenteval_memory_path)
        store.record(fixture)
        signature = failure_signature(fixture)
        recurrence = store.recurrence_count(
            effect_type=fixture.effect_type,
            adapter_id=fixture.adapter_id,
            failure_category=fixture.failure_category,
            invariant=fixture.invariant,
        )
        emit(
            {
                "signature": signature,
                "occurrence_count": recurrence,
                "fixture": fixture.model_dump(mode="json"),
            },
            as_json=as_json,
            human=(
                f"Recorded failure fixture for [bold]{manifest_id}[/bold] "
                f"(category={failure_category!r}); seen {recurrence} time(s) "
                f"with this exact shape (signature {signature})."
            ),
        )

    run_guarded(as_json, _do)


@agenteval_app.command("history")
def history(ctx: typer.Context) -> None:
    """Summarize recorded failure signatures in this workspace's
    failure-memory store, most recurrent first."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        store = FailureMemoryStore(workspace.agenteval_memory_path)
        summaries = store.summarize()
        emit(
            {"summaries": [s.model_dump(mode="json") for s in summaries]},
            as_json=as_json,
            human=(
                "\n".join(
                    f"{s.occurrence_count}x  {s.effect_type} / {s.adapter_id} / "
                    f"{s.failure_category}" + (f" ({s.invariant})" if s.invariant else "")
                    for s in summaries
                )
                or "No failures recorded yet."
            ),
        )

    run_guarded(as_json, _do)


__all__ = ["agenteval_app"]
