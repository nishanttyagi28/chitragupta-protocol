from __future__ import annotations

from typing import Annotated

import typer

from chitragupta.cli.common import emit, run_guarded
from chitragupta.cli.workspace import Workspace

audit_app = typer.Typer(help="Inspect and verify the append-only audit journal.")


@audit_app.command("list")
def list_events(ctx: typer.Context) -> None:
    """List all audit events in sequence order."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        audit = workspace.open_audit()
        events = audit.all_events()
        if as_json:
            emit({"events": [e.model_dump(mode="json") for e in events]}, as_json=True)
            return
        for e in events:
            typer.echo(
                f"[{e.sequence}] {e.timestamp.isoformat()} {e.event_type} "
                f"decision={e.decision} manifest_id={e.manifest_id} grant_id={e.grant_id}"
            )

    run_guarded(as_json, _do)


@audit_app.command("show")
def show(ctx: typer.Context, manifest_id: Annotated[str, typer.Argument()]) -> None:
    """Show all audit events for one manifest_id."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        audit = workspace.open_audit()
        events = audit.events_for_manifest(manifest_id)
        if as_json:
            emit({"events": [e.model_dump(mode="json") for e in events]}, as_json=True)
            return
        if not events:
            typer.echo(f"No audit events found for manifest_id={manifest_id!r}")
        for e in events:
            typer.echo(
                f"[{e.sequence}] {e.timestamp.isoformat()} {e.event_type} "
                f"{e.from_state} -> {e.to_state} decision={e.decision}"
            )

    run_guarded(as_json, _do)


@audit_app.command("verify")
def verify(ctx: typer.Context) -> None:
    """Verify the audit journal's hash chain has not been tampered with."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        audit = workspace.open_audit()
        audit.verify_chain()
        emit(
            {"verified": True, "event_count": len(audit.all_events())},
            as_json=as_json,
            human="Audit chain verified: no tampering detected.",
        )

    run_guarded(as_json, _do)


__all__ = ["audit_app"]
