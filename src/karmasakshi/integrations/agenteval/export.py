"""Export a failed or mismatched production execution as a regression fixture."""

from __future__ import annotations

from pathlib import Path

from karmasakshi.adapters.base import CommitResult, OutcomeProof
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.integrations.agenteval.model import RegressionFixture


def export_regression_fixture(
    *,
    manifest: EffectManifest,
    failure_category: str,
    commit_result: CommitResult | None = None,
    outcome_proof: OutcomeProof | None = None,
    invariant: str | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> RegressionFixture:
    """Build a :class:`RegressionFixture` containing only redacted,
    reproducible information -- no credentials, no raw sensitive data.

    ``manifest.parameters`` are already schema-restricted to str/int/bool/None
    and size-limited (see docs/effect-manifest.md), so they are safe to
    include directly as the normalized inputs.
    """
    return RegressionFixture(
        exported_at=clock.now(),
        effect_type=manifest.effect_type,
        adapter_id=manifest.adapter.adapter_id,
        adapter_version=manifest.adapter.adapter_version,
        normalized_inputs=dict(manifest.parameters),
        expected_effect={
            "target_resource": manifest.target_resource,
            "expected_after_state_digest": manifest.expected_after_state_digest,
        },
        observed_outcome={
            "commit_success": commit_result.success if commit_result is not None else None,
            "matched_expected": (
                outcome_proof.matched_expected if outcome_proof is not None else None
            ),
            "detail": (
                (outcome_proof.detail if outcome_proof is not None else None)
                or (commit_result.detail if commit_result is not None else None)
            ),
        },
        failure_category=failure_category,
        invariant=invariant,
        reproduction_metadata={
            "manifest_hash": manifest.canonical_hash(),
            "idempotency_key": manifest.idempotency_key,
        },
    )


def write_fixture(fixture: RegressionFixture, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(fixture.model_dump_json(indent=2), encoding="utf-8")
    return path


__all__ = ["export_regression_fixture", "write_fixture"]
