from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from karmasakshi.causal.graph import CausalEffectGraph
from karmasakshi.cli.common import console, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.passports import build_passport, render_passport_html, render_passport_markdown


def passport(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    fmt: Annotated[str, typer.Option("--format", help="json, markdown, or html")] = "markdown",
    grant_id: Annotated[str | None, typer.Option()] = None,
    output: Annotated[Path | None, typer.Option("-o", "--output")] = None,
) -> None:
    """Generate an Action Passport for a manifest: what was proposed, approved,
    executed, and observed, plus cryptographic verification status."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        sealed = workspace.load_sealed_manifest(manifest_id)
        grant = workspace.load_grant(grant_id) if grant_id else None
        engine = workspace.build_engine()
        workspace.reconstruct_lifecycle_state(engine, manifest_id)
        commit_result = workspace.load_commit_result(manifest_id)
        outcome_proof = workspace.load_outcome_proof(manifest_id)
        compensation_result = workspace.load_compensation_result(manifest_id)
        assessment = workspace.load_assessment(manifest_id)
        causal_links = workspace.load_all_causal_links()
        causal_graph = CausalEffectGraph(links=causal_links) if causal_links else None

        p = build_passport(
            sealed=sealed,
            keyring=engine.context.keyring,
            audit=engine.context.audit,
            lifecycle_state=engine.get_lifecycle_state(manifest_id).value,
            grant=grant,
            grant_store=engine.context.grant_store,
            commit_result=commit_result,
            outcome_proof=outcome_proof,
            compensation_result=compensation_result,
            assessment=assessment,
            causal_graph=causal_graph,
        )

        if fmt == "json":
            text = p.model_dump_json(indent=2)
        elif fmt == "html":
            text = render_passport_html(p)
        else:
            text = render_passport_markdown(p)

        if output:
            output.write_text(text, encoding="utf-8")
            console.print(f"Wrote passport to {output}")
        else:
            console.print(text)

    run_guarded(as_json, _do)


__all__ = ["passport"]
