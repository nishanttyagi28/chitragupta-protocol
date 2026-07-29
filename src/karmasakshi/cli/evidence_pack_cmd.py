"""Build and independently (offline) verify portable Evidence Packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from karmasakshi.cli.common import console, emit, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.passports import build_passport_v2
from karmasakshi.portable import EvidencePack, build_evidence_pack, verify_evidence_pack

evidence_pack_app = typer.Typer(help="Build and offline-verify portable Evidence Packs.")


@evidence_pack_app.command("build")
def build(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    grant_id: Annotated[str | None, typer.Option()] = None,
    output: Annotated[Path | None, typer.Option("-o", "--output")] = None,
) -> None:
    """Build a self-contained, offline-verifiable Evidence Pack for one manifest."""
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

        passport = build_passport_v2(
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
        pack = build_evidence_pack(
            passport=passport,
            sealed_manifest=sealed,
            audit=engine.context.audit,
            keyring=engine.context.keyring,
            grant=grant,
        )
        text = pack.model_dump_json(indent=2)
        if output:
            output.write_text(text, encoding="utf-8")
            console.print(f"Wrote evidence pack to {output}")
        else:
            console.print(text)

    run_guarded(as_json, _do)


@evidence_pack_app.command("verify")
def verify(
    ctx: typer.Context,
    pack_file: Annotated[Path, typer.Argument(help="Path to a JSON Evidence Pack file")],
) -> None:
    """Independently verify an Evidence Pack file entirely offline.

    Uses only the pack's own contents -- no workspace keys, stores, or
    audit journal are consulted. See docs/portable-evidence.md.
    """
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        raw = pack_file.read_text(encoding="utf-8")
        pack = EvidencePack.model_validate(json.loads(raw))
        result = verify_evidence_pack(pack)
        emit(
            result.model_dump(mode="json"),
            as_json=as_json,
            human=(
                f"Evidence pack for [bold]{pack.manifest_id}[/bold]: "
                f"{'VERIFIED' if result.all_verified else 'FAILED'}"
                + (f" ({'; '.join(result.reasons)})" if result.reasons else "")
            ),
        )
        if not result.all_verified:
            raise typer.Exit(code=2)

    run_guarded(as_json, _do)


__all__ = ["evidence_pack_app"]
