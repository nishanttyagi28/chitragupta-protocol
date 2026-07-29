"""CLI: sign and evaluate independent witness statements (Phase 9)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

import typer

from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.witness import (
    WitnessPolicy,
    sign_witness_statement,
)

witness_app = typer.Typer(help="Independent witness statements and PROVE-time quorum.")


@witness_app.command("sign")
def witness_sign(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    witness_id: Annotated[str, typer.Option()],
    key_id: Annotated[str, typer.Option(help="Signing key id in the workspace")],
    observed_digest: Annotated[str, typer.Option("--observed-digest")],
    matched_expected: Annotated[bool, typer.Option("--matched/--mismatched")] = True,
    witness_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.HUMAN,
    required_witnesses: Annotated[int, typer.Option()] = 1,
    ttl_seconds: Annotated[int, typer.Option()] = 3600,
) -> None:
    """Sign one independent witness statement for a verified effect outcome."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        sealed = workspace.load_sealed_manifest(manifest_id)
        signing_key = workspace.load_signing_key(key_id)
        policy = WitnessPolicy(required_witnesses=required_witnesses)
        now = datetime.now(timezone.utc)
        statement = sign_witness_statement(
            statement_id=str(uuid.uuid4()),
            manifest_hash=sealed.seal.manifest_hash,
            witness_policy_hash=policy.policy_hash(),
            observed_after_state_digest=observed_digest,
            matched_expected=matched_expected,
            witness=Principal(principal_id=witness_id, principal_type=witness_type),
            signing_key=signing_key,
            expires_at=now + timedelta(seconds=ttl_seconds),
            nonce=uuid.uuid4().hex,
        )
        path = workspace.save_witness_statement(statement)
        emit(
            statement.model_dump(mode="json"),
            as_json=as_json,
            human=(
                f"Recorded witness from [bold]{witness_id}[/bold] "
                f"(matched={matched_expected}) at {path}"
            ),
        )

    run_guarded(as_json, _do)


@witness_app.command("evaluate")
def witness_evaluate(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    observed_digest: Annotated[str, typer.Option("--observed-digest")],
    actor_id: Annotated[str, typer.Option()] = "actor-1",
    subject_id: Annotated[str, typer.Option()] = "executor-1",
    actor_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.AGENT,
    subject_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.AGENT,
    required_witnesses: Annotated[int, typer.Option()] = 1,
    assert_quorum: Annotated[bool, typer.Option("--assert/--no-assert")] = False,
) -> None:
    """Evaluate (and optionally assert) independent witness quorum."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        sealed = workspace.load_sealed_manifest(manifest_id)
        engine = workspace.build_engine()
        policy = WitnessPolicy(required_witnesses=required_witnesses)
        statements = workspace.load_witness_statements(sealed.seal.manifest_hash)
        actor = Principal(principal_id=actor_id, principal_type=actor_type)
        subject = Principal(principal_id=subject_id, principal_type=subject_type)
        if assert_quorum:
            result = engine.prove_with_witness_quorum(
                sealed,
                statements=statements,
                policy=policy,
                expected_after_state_digest=observed_digest,
                actor=actor,
                subject=subject,
            )
        else:
            result = engine.evaluate_witnesses(
                sealed,
                statements=statements,
                policy=policy,
                expected_after_state_digest=observed_digest,
                actor=actor,
                subject=subject,
            )
        emit(
            result.model_dump(mode="json"),
            as_json=as_json,
            human=(
                f"Witness quorum {'SATISFIED' if result.satisfied else 'NOT MET'} "
                f"(accepted={len(result.accepted_witness_ids)}/"
                f"{required_witnesses})"
            ),
        )

    run_guarded(as_json, _do)


__all__ = ["witness_app", "witness_evaluate", "witness_sign"]
