from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

import typer

from karmasakshi.approval import ApprovalPolicy, build_approval_policy_bundle
from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.duty import SeparationOfDutyPolicy, build_separation_of_duty_policy_bundle
from karmasakshi.intelligence import IntelligencePolicy
from karmasakshi.intelligence.policy import build_policy_bundle
from karmasakshi.policy import seal_policy_bundle, verify_policy_bundle

policy_app = typer.Typer(help="Create, sign, and verify signed Effect Intelligence policy bundles.")


@policy_app.command("create")
def create(
    ctx: typer.Context,
    bundle_id: Annotated[str, typer.Argument()],
    issuer_id: Annotated[str, typer.Option()],
    issuer_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.HUMAN,
    bundle_version: Annotated[str, typer.Option()] = "1.0",
    effective_seconds: Annotated[
        int, typer.Option(help="How long the bundle is effective for, starting now")
    ] = 30 * 24 * 3600,
    tenant_id: Annotated[str | None, typer.Option()] = None,
    block_threshold: Annotated[int, typer.Option()] = 85,
    review_threshold: Annotated[int, typer.Option()] = 40,
    max_delegation_depth: Annotated[int, typer.Option()] = 8,
    restricted_effect_type: Annotated[
        list[str], typer.Option("--restricted-effect-type", help="repeatable")
    ] = [],  # noqa: B006
    sensitive_target_pattern: Annotated[
        list[str], typer.Option("--sensitive-target-pattern", help="repeatable regex")
    ] = [],  # noqa: B006
) -> None:
    """Build an unsigned policy bundle wrapping an IntelligencePolicy and
    save it to the workspace, ready for ``policy sign``.

    Invariant #30 applies here (see docs/policy-bundles.md): ``issuer``
    must be a human or service principal, never an agent.
    """
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        workspace.ensure_initialized()
        now = datetime.now(timezone.utc)
        policy = IntelligencePolicy(
            block_threshold=block_threshold,
            review_threshold=review_threshold,
            max_delegation_depth=max_delegation_depth,
            restricted_effect_types=tuple(restricted_effect_type),
            sensitive_target_patterns=tuple(sensitive_target_pattern),
        )
        bundle = build_policy_bundle(
            policy,
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            issuer=Principal(principal_id=issuer_id, principal_type=issuer_type),
            created_at=now,
            effective_from=now,
            effective_until=now + timedelta(seconds=effective_seconds),
            tenant_id=tenant_id,
        )
        path = workspace.save_unsigned_policy_bundle(bundle)
        emit(
            {"bundle_id": bundle_id, "policy_hash": bundle.canonical_hash(), "path": str(path)},
            as_json=as_json,
            human=f"Created unsigned policy bundle [bold]{bundle_id}[/bold] -> {path}",
        )

    run_guarded(as_json, _do)


@policy_app.command("create-approval")
def create_approval(
    ctx: typer.Context,
    bundle_id: Annotated[str, typer.Argument()],
    issuer_id: Annotated[str, typer.Option()],
    issuer_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.HUMAN,
    bundle_version: Annotated[str, typer.Option()] = "1.0",
    effective_seconds: Annotated[int, typer.Option()] = 30 * 24 * 3600,
    tenant_id: Annotated[str | None, typer.Option()] = None,
    required_approvals: Annotated[int, typer.Option()] = 1,
    required_role: Annotated[list[str], typer.Option("--required-role", help="repeatable")] = [],  # noqa: B006
    forbid_proposer_as_approver: Annotated[bool, typer.Option()] = True,
    forbid_subject_as_approver: Annotated[bool, typer.Option()] = True,
    veto_on_any_dissent: Annotated[bool, typer.Option()] = True,
    cooling_off_seconds: Annotated[int, typer.Option()] = 0,
) -> None:
    """Build an unsigned approval (quorum) policy bundle -- an
    ``ApprovalPolicy`` wrapped in the same signed ``PolicyBundle``
    envelope as an Effect Intelligence policy (``policy_type ==
    "approval.v1"``). Sign it with `policy sign` and verify it with
    `policy verify`, exactly like an intelligence policy bundle."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        workspace.ensure_initialized()
        now = datetime.now(timezone.utc)
        policy = ApprovalPolicy(
            required_approvals=required_approvals,
            required_roles=tuple(required_role),
            forbid_proposer_as_approver=forbid_proposer_as_approver,
            forbid_subject_as_approver=forbid_subject_as_approver,
            veto_on_any_dissent=veto_on_any_dissent,
            cooling_off_seconds=cooling_off_seconds,
        )
        bundle = build_approval_policy_bundle(
            policy,
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            issuer=Principal(principal_id=issuer_id, principal_type=issuer_type),
            created_at=now,
            effective_from=now,
            effective_until=now + timedelta(seconds=effective_seconds),
            tenant_id=tenant_id,
        )
        path = workspace.save_unsigned_policy_bundle(bundle)
        emit(
            {"bundle_id": bundle_id, "policy_hash": bundle.canonical_hash(), "path": str(path)},
            as_json=as_json,
            human=f"Created unsigned approval policy bundle [bold]{bundle_id}[/bold] -> {path}",
        )

    run_guarded(as_json, _do)


@policy_app.command("create-separation")
def create_separation(
    ctx: typer.Context,
    bundle_id: Annotated[str, typer.Argument()],
    issuer_id: Annotated[str, typer.Option()],
    issuer_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.HUMAN,
    bundle_version: Annotated[str, typer.Option()] = "1.0",
    effective_seconds: Annotated[int, typer.Option()] = 30 * 24 * 3600,
    tenant_id: Annotated[str | None, typer.Option()] = None,
    forbidden_pair: Annotated[
        list[str],
        typer.Option(
            "--forbidden-pair",
            help="repeatable, format 'role_a:role_b' (e.g. 'sealer:approver'); "
            "if none given, uses the built-in default matrix",
        ),
    ] = [],  # noqa: B006
) -> None:
    """Build an unsigned separation-of-duty policy bundle -- a
    ``SeparationOfDutyPolicy`` (a forbidden role-pair matrix) wrapped in
    the same signed ``PolicyBundle`` envelope as the other policy types
    (``policy_type == "separation.v1"``). Sign it with `policy sign` and
    verify it with `policy verify`, exactly like the others."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        workspace.ensure_initialized()
        now = datetime.now(timezone.utc)
        pairs: list[tuple[str, str]] = []
        for entry in forbidden_pair:
            role_a, sep, role_b = entry.partition(":")
            if not sep:
                raise typer.BadParameter(f"--forbidden-pair must be 'role_a:role_b', got {entry!r}")
            pairs.append((role_a, role_b))
        policy = (
            SeparationOfDutyPolicy(forbidden_role_pairs=tuple(pairs))
            if pairs
            else SeparationOfDutyPolicy()
        )
        bundle = build_separation_of_duty_policy_bundle(
            policy,
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            issuer=Principal(principal_id=issuer_id, principal_type=issuer_type),
            created_at=now,
            effective_from=now,
            effective_until=now + timedelta(seconds=effective_seconds),
            tenant_id=tenant_id,
        )
        path = workspace.save_unsigned_policy_bundle(bundle)
        emit(
            {"bundle_id": bundle_id, "policy_hash": bundle.canonical_hash(), "path": str(path)},
            as_json=as_json,
            human=f"Created unsigned separation-of-duty policy bundle [bold]{bundle_id}[/bold] -> {path}",  # noqa: E501
        )

    run_guarded(as_json, _do)


@policy_app.command("sign")
def sign(
    ctx: typer.Context,
    bundle_id: Annotated[str, typer.Argument()],
    key_id: Annotated[str, typer.Option(help="Signing key id in the workspace")],
) -> None:
    """Sign an unsigned policy bundle's canonical hash, producing a sealed bundle."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        bundle = workspace.load_unsigned_policy_bundle(bundle_id)
        signing_key = workspace.load_signing_key(key_id)
        sealed = seal_policy_bundle(bundle, signing_key)
        path = workspace.save_sealed_policy_bundle(sealed)
        emit(
            {
                "bundle_id": bundle_id,
                "bundle_hash": sealed.seal.bundle_hash,
                "path": str(path),
            },
            as_json=as_json,
            human=(
                f"Sealed policy bundle [bold]{bundle_id}[/bold]: "
                f"{sealed.seal.bundle_hash} -> {path}"
            ),
        )

    run_guarded(as_json, _do)


@policy_app.command("verify")
def verify(ctx: typer.Context, bundle_id: Annotated[str, typer.Argument()]) -> None:
    """Verify a sealed policy bundle's signature, integrity, and effective window."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        sealed = workspace.load_sealed_policy_bundle(bundle_id)
        keyring = workspace.load_keyring()
        verify_policy_bundle(sealed, keyring, now=datetime.now(timezone.utc))
        emit(
            {
                "bundle_id": bundle_id,
                "valid": True,
                "policy_type": sealed.bundle.policy_type,
                "effective_from": sealed.bundle.effective_from.isoformat(),
                "effective_until": (
                    sealed.bundle.effective_until.isoformat()
                    if sealed.bundle.effective_until
                    else None
                ),
            },
            as_json=as_json,
            human=f"Policy bundle [bold]{bundle_id}[/bold] is valid.",
        )

    run_guarded(as_json, _do)


__all__ = ["policy_app"]
