from __future__ import annotations

import uuid
from typing import Annotated

import typer

from karmasakshi.causal.graph import CausalEffectGraph, verify_causal_graph
from karmasakshi.causal.model import CausalRelationship
from karmasakshi.causal.signing import sign_causal_link
from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType

causal_app = typer.Typer(help="Record and verify causal links between manifests (advisory only).")


@causal_app.command("record")
def record(
    ctx: typer.Context,
    parent_manifest_id: Annotated[str, typer.Argument()],
    child_manifest_id: Annotated[str, typer.Argument()],
    recorded_by_id: Annotated[str, typer.Option("--recorded-by-id")],
    key_id: Annotated[str, typer.Option(help="Signing key id in the workspace")],
    recorded_by_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.AGENT,
    relationship: Annotated[CausalRelationship, typer.Option()] = "triggers",
) -> None:
    """Sign and record a causal link from ``parent_manifest_id`` to
    ``child_manifest_id``. Advisory only -- see
    docs/causal-effect-graphs.md; unlike `grant issue`/`approve`, there is
    no principal-type restriction on `--recorded-by-id` (a causal link is
    a factual record, not an authorization decision)."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        parent_hash = workspace.load_manifest_any(parent_manifest_id).canonical_hash()
        child_hash = workspace.load_manifest_any(child_manifest_id).canonical_hash()
        signing_key = workspace.load_signing_key(key_id)
        link = sign_causal_link(
            link_id=str(uuid.uuid4()),
            parent_manifest_hash=parent_hash,
            child_manifest_hash=child_hash,
            relationship=relationship,
            recorded_by=Principal(principal_id=recorded_by_id, principal_type=recorded_by_type),
            signing_key=signing_key,
            nonce=uuid.uuid4().hex,
        )
        path = workspace.save_causal_link(link)
        emit(
            {"link_id": link.link_id, "relationship": relationship, "path": str(path)},
            as_json=as_json,
            human=(
                f"Recorded causal link [bold]{link.link_id}[/bold]: "
                f"{parent_manifest_id} --{relationship}--> {child_manifest_id} -> {path}"
            ),
        )

    run_guarded(as_json, _do)


@causal_app.command("verify")
def verify(ctx: typer.Context) -> None:
    """Verify every causal link ever recorded in this workspace: every
    signature independently, and the whole graph for cycles."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        links = workspace.load_all_causal_links()
        keyring = workspace.load_keyring()
        graph = CausalEffectGraph(links=links)
        result = verify_causal_graph(graph, keyring)
        emit(
            {
                "verified": result.verified,
                "has_cycle": result.has_cycle,
                "invalid_link_ids": list(result.invalid_link_ids),
                "node_count": result.node_count,
                "edge_count": result.edge_count,
                "reason": result.reason,
            },
            as_json=as_json,
            human=f"Causal graph {'VERIFIED' if result.verified else 'INVALID'}: {result.reason}",
        )

    run_guarded(as_json, _do)


__all__ = ["causal_app"]
