"""Create, sign, verify, and substitute under Decision Envelopes (Phase 6)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Annotated

import typer

from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.domain.common import AdapterIdentity, MonetaryAmount, Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.envelope import (
    build_decision_envelope,
    enum_of,
    exact,
    integer_range,
    monetary_range,
    seal_decision_envelope,
    substitute_parameters,
    verify_decision_envelope,
)
from karmasakshi.envelope.constraints import ParameterConstraint

envelope_app = typer.Typer(help="Create, seal, verify, and substitute Decision Envelopes.")


def _parse_constraint(spec: str) -> tuple[str, ParameterConstraint]:
    """Parse ``name=kind:...`` constraint specs.

    Examples:
      amount=monetary:INR:0:150000
      recipient=exact:customer-priya
      currency=enum:INR,USD
      quantity=int:1:10
    """
    name, sep, rest = spec.partition("=")
    if not sep or not name or not rest:
        raise typer.BadParameter("--constraint must be 'name=kind:...' (exact|enum|int|monetary)")
    kind, sep2, payload = rest.partition(":")
    if not sep2:
        raise typer.BadParameter(f"constraint {name!r} missing kind payload")
    if kind == "exact":
        value: str | int | bool | None
        if payload == "null":
            value = None
        elif payload in {"true", "false"}:
            value = payload == "true"
        else:
            try:
                value = int(payload)
            except ValueError:
                value = payload
        return name, exact(value)
    if kind == "enum":
        parts = tuple(p for p in payload.split(",") if p)
        coerced: list[str | int | bool | None] = []
        for part in parts:
            if part == "null":
                coerced.append(None)
            elif part in {"true", "false"}:
                coerced.append(part == "true")
            else:
                try:
                    coerced.append(int(part))
                except ValueError:
                    coerced.append(part)
        return name, enum_of(*coerced)
    if kind == "int":
        lo_s, sep3, hi_s = payload.partition(":")
        if not sep3:
            raise typer.BadParameter("int constraint needs min:max (either may be empty)")
        min_int = int(lo_s) if lo_s else None
        max_int = int(hi_s) if hi_s else None
        return name, integer_range(min_int=min_int, max_int=max_int)
    if kind == "monetary":
        currency, sep3, remainder = payload.partition(":")
        lo_s, sep4, hi_s = remainder.partition(":")
        if not sep3 or not sep4:
            raise typer.BadParameter(
                "monetary constraint needs currency:min_minor:max_minor (either bound may be empty)"
            )
        return name, monetary_range(
            currency=currency,
            min_minor_units=int(lo_s) if lo_s else None,
            max_minor_units=int(hi_s) if hi_s else None,
        )
    raise typer.BadParameter(f"unknown constraint kind {kind!r}")


@envelope_app.command("create")
def create_envelope(
    ctx: typer.Context,
    envelope_id: Annotated[str, typer.Argument()],
    effect_type: Annotated[str, typer.Option()],
    adapter_id: Annotated[str, typer.Option()],
    adapter_version: Annotated[str, typer.Option()] = "1.0",
    target_resource: Annotated[
        list[str], typer.Option("--target-resource", help="repeatable allow-list entry")
    ] = [],  # noqa: B006
    constraint: Annotated[
        list[str],
        typer.Option(
            "--constraint",
            help="repeatable name=kind:... (exact|enum|int|monetary)",
        ),
    ] = [],  # noqa: B006
    issuer_id: Annotated[str, typer.Option()] = "envelope-issuer",
    issuer_type: Annotated[PrincipalType, typer.Option()] = PrincipalType.HUMAN,
    key_id: Annotated[str, typer.Option()] = "issuer",
    ttl_seconds: Annotated[int, typer.Option()] = 3600,
    max_cost_currency: Annotated[str | None, typer.Option()] = None,
    max_cost_minor_units: Annotated[int | None, typer.Option()] = None,
    causal_graph_id: Annotated[
        str | None,
        typer.Option(help="Optional sealed causal graph to pin inside this envelope"),
    ] = None,
    sign: Annotated[bool, typer.Option("--sign/--no-sign")] = True,
) -> None:
    """Build (and optionally seal) a Decision Envelope in the workspace."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        workspace.ensure_initialized()
        if not target_resource:
            raise typer.BadParameter("at least one --target-resource is required")
        constraints = dict(_parse_constraint(spec) for spec in constraint)
        now = datetime.now(timezone.utc)
        max_cost = None
        if max_cost_currency is not None and max_cost_minor_units is not None:
            max_cost = MonetaryAmount(currency=max_cost_currency, minor_units=max_cost_minor_units)
        graph_hash = None
        if causal_graph_id is not None:
            graph = workspace.load_causal_graph(causal_graph_id)
            graph.verify(workspace.load_keyring())
            graph_hash = graph.canonical_hash()
        envelope = build_decision_envelope(
            envelope_id=envelope_id,
            effect_type=effect_type,
            adapter=AdapterIdentity(adapter_id=adapter_id, adapter_version=adapter_version),
            target_resources=tuple(target_resource),
            parameter_constraints=constraints,
            issuer=Principal(principal_id=issuer_id, principal_type=issuer_type),
            not_before=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            signing_key_id=key_id,
            created_at=now,
            max_estimated_cost=max_cost,
            causal_graph_hash=graph_hash,
        )
        if sign:
            signing_key = workspace.load_signing_key(key_id)
            envelope = seal_decision_envelope(envelope, signing_key)
            verify_decision_envelope(envelope, workspace.load_keyring(), now=now)
        path = workspace.save_decision_envelope(envelope)
        emit(
            {
                "envelope_id": envelope.envelope_id,
                "envelope_hash": envelope.canonical_hash(),
                "signed": envelope.signature is not None,
                "path": str(path),
            },
            as_json=as_json,
            human=(
                f"{'Sealed' if envelope.signature else 'Created unsigned'} decision envelope "
                f"[bold]{envelope_id}[/bold] -> {path}"
            ),
        )

    run_guarded(as_json, _do)


@envelope_app.command("verify")
def verify_envelope_cmd(ctx: typer.Context, envelope_id: Annotated[str, typer.Argument()]) -> None:
    """Verify signature, integrity, and effective window of a stored envelope."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        envelope = workspace.load_decision_envelope(envelope_id)
        verify_decision_envelope(envelope, workspace.load_keyring(), now=datetime.now(timezone.utc))
        emit(
            {
                "envelope_id": envelope.envelope_id,
                "envelope_hash": envelope.canonical_hash(),
                "verified": True,
            },
            as_json=as_json,
            human=(
                f"Decision envelope [bold]{envelope_id}[/bold] verified: "
                f"{envelope.canonical_hash()}"
            ),
        )

    run_guarded(as_json, _do)


@envelope_app.command("substitute")
def substitute_cmd(
    ctx: typer.Context,
    envelope_id: Annotated[str, typer.Argument()],
    choice: Annotated[
        list[str],
        typer.Option("--choice", help="repeatable name=value (int/bool/null/string)"),
    ] = [],  # noqa: B006
) -> None:
    """Deterministically resolve parameter choices under a sealed envelope."""
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        envelope = workspace.load_decision_envelope(envelope_id)
        verify_decision_envelope(envelope, workspace.load_keyring(), now=datetime.now(timezone.utc))
        choices: dict[str, str | int | bool | None] = {}
        for spec in choice:
            name, sep, raw = spec.partition("=")
            if not sep:
                raise typer.BadParameter(f"--choice must be name=value, got {spec!r}")
            if raw == "null":
                choices[name] = None
            elif raw in {"true", "false"}:
                choices[name] = raw == "true"
            else:
                try:
                    choices[name] = int(raw)
                except ValueError:
                    choices[name] = raw
        resolved = substitute_parameters(envelope, choices)
        emit(
            {
                "envelope_id": envelope.envelope_id,
                "parameters": resolved,
            },
            as_json=as_json,
            human=f"Substituted parameters: {json.dumps(resolved, sort_keys=True)}",
        )

    run_guarded(as_json, _do)


__all__ = ["envelope_app"]
