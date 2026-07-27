"""The ``chitragupta`` CLI entrypoint."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from chitragupta import __version__
from chitragupta.cli.audit_cmd import audit_app
from chitragupta.cli.common import console, emit
from chitragupta.cli.demo_cmd import demo
from chitragupta.cli.doctor_cmd import doctor
from chitragupta.cli.execute_cmd import compensate, execute
from chitragupta.cli.execute_cmd import verify as execute_verify
from chitragupta.cli.grant_cmd import grant_app
from chitragupta.cli.key_cmd import key_app
from chitragupta.cli.manifest_cmd import prepare, seal
from chitragupta.cli.passport_cmd import passport
from chitragupta.cli.workspace import Workspace, default_workspace_path

app = typer.Typer(
    name="chitragupta",
    help="Chitragupta Protocol -- seal the intended effect, verify the actual outcome.",
    no_args_is_help=True,
)

app.add_typer(audit_app, name="audit")
app.add_typer(grant_app, name="grant")
app.add_typer(key_app, name="key")


@app.callback()
def main_callback(
    ctx: typer.Context,
    workspace: Annotated[
        Path | None, typer.Option("--workspace", help="Workspace directory (default: .chitragupta)")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Machine-readable JSON output")
    ] = False,
) -> None:
    ws_path = workspace or default_workspace_path()
    ctx.obj = {"workspace": Workspace(ws_path), "json": json_output}


@app.command()
def init(ctx: typer.Context) -> None:
    """Initialize a new local workspace (keys/, manifests/, grants/)."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]
    workspace.ensure_initialized()
    emit(
        {"workspace": str(workspace.root)},
        as_json=as_json,
        human=f"Initialized workspace at [bold]{workspace.root}[/bold]",
    )


@app.command()
def version() -> None:
    """Print the installed chitragupta version."""
    console.print(__version__)


app.command("prepare")(prepare)
app.command("seal")(seal)
app.command("execute")(execute)
app.command("verify")(execute_verify)
app.command("compensate")(compensate)
app.command("passport")(passport)
app.command("demo")(demo)
app.command("doctor")(doctor)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

__all__ = ["app", "main"]
