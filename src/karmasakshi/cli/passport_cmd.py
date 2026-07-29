from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from karmasakshi.cli.common import console, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.passports import (
    build_passport,
    build_passport_v2,
    render_passport_html,
    render_passport_markdown,
    render_passport_v2_html,
    render_passport_v2_markdown,
)


def passport(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    fmt: Annotated[str, typer.Option("--format", help="json, markdown, or html")] = "markdown",
    grant_id: Annotated[str | None, typer.Option()] = None,
    version: Annotated[
        str,
        typer.Option("--version", help="Passport schema version: v1 (default) or v2"),
    ] = "v1",
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
        lifecycle_state = engine.get_lifecycle_state(manifest_id).value

        ver = version.strip().lower()
        if ver in {"v2", "2", "2.0"}:
            p2 = build_passport_v2(
                sealed=sealed,
                keyring=engine.context.keyring,
                audit=engine.context.audit,
                lifecycle_state=lifecycle_state,
                grant=grant,
                grant_store=engine.context.grant_store,
                commit_result=commit_result,
                outcome_proof=outcome_proof,
                compensation_result=compensation_result,
                assessment=assessment,
                tenant_id=engine.context.tenant_id,
            )
            if fmt == "json":
                text = p2.model_dump_json(indent=2)
            elif fmt == "html":
                text = render_passport_v2_html(p2)
            else:
                text = render_passport_v2_markdown(p2)
        elif ver in {"v1", "1", "1.0"}:
            p1 = build_passport(
                sealed=sealed,
                keyring=engine.context.keyring,
                audit=engine.context.audit,
                lifecycle_state=lifecycle_state,
                grant=grant,
                grant_store=engine.context.grant_store,
                commit_result=commit_result,
                outcome_proof=outcome_proof,
                compensation_result=compensation_result,
                assessment=assessment,
            )
            if fmt == "json":
                text = p1.model_dump_json(indent=2)
            elif fmt == "html":
                text = render_passport_html(p1)
            else:
                text = render_passport_markdown(p1)
        else:
            raise ValueError("passport --version must be v1 or v2")

        if output:
            output.write_text(text, encoding="utf-8")
            console.print(f"Wrote passport to {output}")
        else:
            console.print(text)

    run_guarded(as_json, _do)


__all__ = ["passport"]
