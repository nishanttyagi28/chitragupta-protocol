from __future__ import annotations

from typing import Annotated

import typer

from karmasakshi.cli.common import console, emit, fail
from karmasakshi.cli.workspace import Workspace

key_app = typer.Typer(help="Manage development signing keys.")


@key_app.command("generate")
def generate(
    ctx: typer.Context,
    key_id: Annotated[str, typer.Argument(help="Identifier for the new key")],
) -> None:
    """Generate a new Ed25519 development signing key in the workspace."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]
    workspace.ensure_initialized()
    if workspace.has_key(key_id):
        fail(f"key_id {key_id!r} already exists", as_json=as_json)
    key = workspace.generate_key(key_id)
    emit(
        {"key_id": key.key_id, "algorithm": key.algorithm},
        as_json=as_json,
        human=f"Generated key [bold]{key.key_id}[/bold] ({key.algorithm}). "
        f"Private key material was never printed.",
    )


@key_app.command("list")
def list_keys(ctx: typer.Context) -> None:
    """List key ids known to this workspace's keyring (public info only)."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]
    if not workspace.is_initialized():
        fail("workspace not initialized; run `karmasakshi init` first", as_json=as_json)
    key_ids = workspace.list_key_ids()
    if as_json:
        emit({"key_ids": key_ids}, as_json=True)
    else:
        if not key_ids:
            console.print("No keys found.")
        for kid in key_ids:
            console.print(f"- {kid}")


__all__ = ["key_app"]
