from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

import typer

from karmasakshi.approval import (
    ApprovalPolicy,
    approval_policy_from_bundle_payload,
    evaluate_quorum,
)
from karmasakshi.approval.model import Decision
from karmasakshi.approval.signing import sign_approval_statement
from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType

approvals_app = typer.Typer(help="Inspect submitted approval statements and quorum status.")


def approve(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    approver_id: Annotated[str, typer.Option()],
    key_id: Annotated[str, typer.Option(help="Signing key id in the workspace")],
    approval_policy_bundle_id: Annotated[str, typer.Option("--approval-policy-bundle-id")],
    approver_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.HUMAN,
    role: Annotated[str | None, typer.Option()] = None,
    decision: Annotated[Decision, typer.Option()] = "approve",
    reason: Annotated[str | None, typer.Option()] = None,
    ttl_seconds: Annotated[int, typer.Option()] = 3600,
) -> None:
    """Sign one approval (or explicit dissent) statement for a manifest,
    bound to one exact sealed manifest and one exact signed approval
    policy bundle. Invariant #30 applies: the approver must be a human or
    service principal, never an agent."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        sealed = workspace.load_sealed_manifest(manifest_id)
        approval_bundle = workspace.load_sealed_policy_bundle(approval_policy_bundle_id)
        signing_key = workspace.load_signing_key(key_id)
        now = datetime.now(timezone.utc)
        statement = sign_approval_statement(
            statement_id=str(uuid.uuid4()),
            manifest_hash=sealed.seal.manifest_hash,
            approval_policy_bundle_hash=approval_bundle.seal.bundle_hash,
            approver=Principal(principal_id=approver_id, principal_type=approver_type),
            decision=decision,
            signing_key=signing_key,
            expires_at=now + timedelta(seconds=ttl_seconds),
            nonce=uuid.uuid4().hex,
            role=role,
            reason=reason,
        )
        path = workspace.save_approval_statement(statement)
        emit(
            {
                "statement_id": statement.statement_id,
                "manifest_id": manifest_id,
                "decision": decision,
                "path": str(path),
            },
            as_json=as_json,
            human=(
                f"Recorded {decision} from [bold]{approver_id}[/bold] "
                f"for manifest {manifest_id} -> {path}"
            ),
        )

    run_guarded(as_json, _do)


@approvals_app.command("inspect")
def inspect(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    approval_policy_bundle_id: Annotated[str, typer.Option("--approval-policy-bundle-id")],
    proposer_id: Annotated[str, typer.Option()],
    subject_id: Annotated[str, typer.Option()],
    proposer_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.AGENT,
    subject_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.AGENT,
) -> None:
    """Evaluate quorum for all approval statements submitted so far for a
    manifest, without issuing a grant (a dry run of what `grant
    issue-with-quorum` would decide)."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        sealed = workspace.load_sealed_manifest(manifest_id)
        approval_bundle = workspace.load_sealed_policy_bundle(approval_policy_bundle_id)
        policy: ApprovalPolicy = approval_policy_from_bundle_payload(approval_bundle.bundle.payload)
        statements = workspace.load_approval_statements(sealed.seal.manifest_hash)
        keyring = workspace.load_keyring()
        result = evaluate_quorum(
            statements,
            policy,
            manifest_hash=sealed.seal.manifest_hash,
            approval_policy_bundle_hash=approval_bundle.seal.bundle_hash,
            keyring=keyring,
            proposer=Principal(principal_id=proposer_id, principal_type=proposer_type),
            subject=Principal(principal_id=subject_id, principal_type=subject_type),
            now=datetime.now(timezone.utc),
        )
        emit(
            {
                "manifest_id": manifest_id,
                "satisfied": result.satisfied,
                "approving_count": result.approving_count,
                "approving_principal_ids": list(result.approving_principal_ids),
                "dissenting_principal_ids": list(result.dissenting_principal_ids),
                "missing_roles": list(result.missing_roles),
                "rejected": [list(r) for r in result.rejected],
                "approval_set_hash": result.approval_set_hash,
                "reason": result.reason,
            },
            as_json=as_json,
            human=f"Quorum {'MET' if result.satisfied else 'NOT MET'}: {result.reason}",
        )

    run_guarded(as_json, _do)


__all__ = ["approvals_app", "approve"]
