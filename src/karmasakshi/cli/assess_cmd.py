from __future__ import annotations

from typing import Annotated

import typer

from karmasakshi.cli.common import emit, run_guarded
from karmasakshi.cli.workspace import Workspace
from karmasakshi.intelligence import AssessmentFacts, derive_facts_from_audit

_TRI_STATE_CHOICES = ("unknown", "yes", "no")


def _tri_state(value: str, *, option_name: str) -> bool | None:
    if value == "unknown":
        return None
    if value == "yes":
        return True
    if value == "no":
        return False
    raise typer.BadParameter(f"{option_name} must be one of {_TRI_STATE_CHOICES}, got {value!r}")


def assess(
    ctx: typer.Context,
    manifest_id: Annotated[str, typer.Argument()],
    delegation_depth: Annotated[int, typer.Option()] = 0,
    historical_recurrence_count: Annotated[int, typer.Option()] = 0,
    historical_failure_count: Annotated[int, typer.Option()] = 0,
    provider_idempotent: Annotated[
        str, typer.Option(help="unknown, yes, or no -- whether the provider guarantees idempotency")
    ] = "unknown",
    compensation_feasible: Annotated[
        str, typer.Option(help="unknown, yes, or no -- whether compensation is confirmed feasible")
    ] = "unknown",
    cross_tenant: Annotated[bool, typer.Option()] = False,
    unusual_parameter_change: Annotated[bool, typer.Option("--unusual-parameter-change")] = False,
    policy_violation: Annotated[
        list[str], typer.Option("--policy-violation", help="repeatable; any value forces BLOCK")
    ] = [],  # noqa: B006
    from_audit_history: Annotated[
        bool,
        typer.Option(
            "--from-audit-history",
            help="derive recurrence/failure facts from this workspace's audit journal "
            "instead of the --historical-* flags",
        ),
    ] = False,
) -> None:
    """Run the deterministic Effect Intelligence Engine over a manifest and
    record the resulting assessment in the workspace's audit journal.

    The recommendation is advisory in this protocol version: it is not yet
    read or enforced by ``authorize``/``execute``. See
    docs/effect-intelligence.md.
    """
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    def _do() -> None:
        manifest = workspace.load_manifest_any(manifest_id)
        engine = workspace.build_engine()
        workspace.reconstruct_lifecycle_state(engine, manifest_id)

        idempotent = _tri_state(provider_idempotent, option_name="--provider-idempotent")
        feasible = _tri_state(compensation_feasible, option_name="--compensation-feasible")

        if from_audit_history:
            facts = derive_facts_from_audit(
                engine.context.audit,
                manifest,
                delegation_depth=delegation_depth,
                provider_idempotent=idempotent,
                compensation_feasible=feasible,
                cross_tenant=cross_tenant,
                unusual_parameter_change=unusual_parameter_change,
                extra_policy_violations=tuple(policy_violation),
            )
        else:
            facts = AssessmentFacts(
                delegation_depth=delegation_depth,
                historical_recurrence_count=historical_recurrence_count,
                historical_failure_count=historical_failure_count,
                provider_idempotent=idempotent,
                compensation_feasible=feasible,
                cross_tenant=cross_tenant,
                unusual_parameter_change=unusual_parameter_change,
                policy_violations=tuple(policy_violation),
            )

        assessment = engine.assess(manifest, facts)
        path = workspace.save_assessment(assessment)
        emit(
            {
                "assessment_id": assessment.assessment_id,
                "manifest_id": assessment.manifest_id,
                "score": assessment.score,
                "risk_level": assessment.risk_level.value,
                "recommendation": assessment.recommendation.value,
                "required_human_approvals": assessment.required_human_approvals,
                "required_service_approvals": assessment.required_service_approvals,
                "cooling_off_period_seconds": assessment.cooling_off_period_seconds,
                "required_witness_quorum": assessment.required_witness_quorum,
                "required_verification_strength": assessment.required_verification_strength.value,
                "explanation": assessment.explanation,
                "path": str(path),
            },
            as_json=as_json,
            human=(
                f"Assessment for [bold]{manifest_id}[/bold]: score={assessment.score}/100 "
                f"risk={assessment.risk_level.value} "
                f"recommendation=[bold]{assessment.recommendation.value}[/bold]\n"
                f"{assessment.explanation}"
            ),
        )

    run_guarded(as_json, _do)


__all__ = ["assess"]
