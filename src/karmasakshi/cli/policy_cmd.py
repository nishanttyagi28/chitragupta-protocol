from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

import typer

from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
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
