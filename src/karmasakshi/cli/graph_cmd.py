"""Create and independently inspect signed causal effect graphs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

import typer

from karmasakshi.causal import build_causal_graph, sign_causal_link
from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace

graph_app = typer.Typer(help="Create and verify signed causal effect graphs.")


@graph_app.command("create")
def create_graph(
    ctx: typer.Context,
    graph_id: Annotated[str, typer.Argument()],
    manifest_id: Annotated[list[str], typer.Option("--manifest-id", help="repeatable")],
    edge: Annotated[
        list[str],
        typer.Option("--edge", help="parent_id:child_id:relation; repeatable"),
    ],
    key_id: Annotated[str, typer.Option()],
) -> None:
    """Create a graph from sealed workspace manifests."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        workspace.ensure_initialized()
        manifests = {item: workspace.load_sealed_manifest(item) for item in manifest_id}
        hashes = {item: sealed.manifest.canonical_hash() for item, sealed in manifests.items()}
        signing_key = workspace.load_signing_key(key_id)
        now = datetime.now(timezone.utc)
        links = []
        for value in edge:
            parent, separator, remainder = value.partition(":")
            child, separator_two, relation = remainder.partition(":")
            if not separator or not separator_two or parent not in hashes or child not in hashes:
                raise typer.BadParameter(
                    "--edge must reference listed manifests as "
                    f"parent:child:relation, got {value!r}"
                )
            links.append(
                sign_causal_link(
                    parent_manifest_hash=hashes[parent],
                    child_manifest_hash=hashes[child],
                    relation=relation,  # type: ignore[arg-type]
                    signing_key=signing_key,
                    created_at=now,
                )
            )
        graph = build_causal_graph(
            graph_id=graph_id,
            node_manifest_hashes=tuple(hashes.values()),
            links=tuple(links),
        )
        graph.verify(workspace.load_keyring())
        path = workspace.save_causal_graph(graph)
        emit(
            {"graph_id": graph_id, "graph_hash": graph.canonical_hash(), "path": str(path)},
            as_json=as_json,
            human=f"Created verified causal graph [bold]{graph_id}[/bold] -> {path}",
        )

    run_guarded(as_json, _do)


@graph_app.command("verify")
def verify_graph(ctx: typer.Context, graph_id: Annotated[str, typer.Argument()]) -> None:
    """Verify every graph link and print its deterministic identity."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        graph = workspace.load_causal_graph(graph_id)
        graph.verify(workspace.load_keyring())
        emit(
            {
                "graph_id": graph.graph_id,
                "graph_hash": graph.canonical_hash(),
                "roots": graph.roots(),
                "verified": True,
            },
            as_json=as_json,
            human=f"Causal graph [bold]{graph_id}[/bold] verified: {graph.canonical_hash()}",
        )

    run_guarded(as_json, _do)


__all__ = ["graph_app"]
