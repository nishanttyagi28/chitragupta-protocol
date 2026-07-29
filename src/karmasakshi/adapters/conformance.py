"""Adapter conformance kit (extreme-v2 Phase 18).

Deterministic structural checks that an :class:`EffectAdapter` obeys the
contract documented in ``docs/adapter-authoring.md``. The kit does **not**
prove provider honesty against a live cloud API; it verifies that a given
in-process adapter instance:

- exposes a stable identity
- prepares manifests that bind that identity
- re-checks preconditions without inventing success
- does not treat ``CommitResult.success`` as independent verification
- reports compensation outcomes honestly (no ``succeeded=True`` without
  ``attempted=True``; irreversible effects refuse honestly)

Callers supply a :class:`ConformanceScenario` that knows how to build a
request and any adapter-specific context for one concrete effect.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from karmasakshi.adapters.base import (
    CommitResult,
    CompensationResult,
    EffectAdapter,
    OutcomeProof,
    PreconditionResult,
)
from karmasakshi.domain.enums import ReversibilityClassification
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.errors import AdapterConformanceError
from karmasakshi.grants.model import ExecutionGrant

CheckFn = Callable[[], None]


@dataclass(frozen=True)
class ConformanceCheckResult:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ConformanceReport:
    adapter_id: str
    adapter_version: str
    checks: tuple[ConformanceCheckResult, ...]
    passed: bool

    def raise_if_failed(self) -> None:
        if self.passed:
            return
        failed = [c for c in self.checks if not c.passed]
        summary = "; ".join(f"{c.name}: {c.detail}" for c in failed)
        raise AdapterConformanceError(
            f"adapter {self.adapter_id}@{self.adapter_version} failed "
            f"conformance ({len(failed)} check(s)): {summary}"
        )


@dataclass
class ConformanceScenario:
    """One concrete effect the kit should exercise against an adapter."""

    request: Any
    context: Any = None
    #: Optional grant object passed to ``adapter.commit`` (adapters may ignore it).
    grant: ExecutionGrant | None = None
    #: When True, expect ``validate_preconditions`` to fail after an optional mutate.
    expect_stale_after_mutate: bool = False
    mutate_external_state: Callable[[], None] | None = None


@dataclass
class AdapterConformanceKit:
    """Run the Phase 18 conformance checklist against one adapter instance."""

    adapter: EffectAdapter
    scenario: ConformanceScenario

    def run(self) -> ConformanceReport:
        results: list[ConformanceCheckResult] = []
        results.append(self._run_named("identity", self._check_identity))

        try:
            manifest = self.adapter.prepare(self.scenario.request, self.scenario.context)
        except Exception as exc:  # noqa: BLE001 — surface as check failure
            results.append(
                ConformanceCheckResult(
                    name="prepare_binds_identity",
                    passed=False,
                    detail=f"prepare raised {type(exc).__name__}: {exc}",
                )
            )
            return self._report(results)

        results.append(
            self._run_named(
                "prepare_binds_identity",
                lambda: self._assert_prepared(manifest),
            )
        )
        results.append(
            self._run_named(
                "preconditions",
                lambda: self._check_preconditions(manifest),
            )
        )
        results.append(
            self._run_named(
                "verify_rejects_uncommitted_forged_success",
                lambda: self._check_verify_before_commit(manifest),
            )
        )
        results.append(self._run_named("commit_shape", lambda: self._check_commit(manifest)))
        results.append(
            self._run_named(
                "compensation_honesty",
                lambda: self._check_compensation(manifest),
            )
        )
        results.append(
            self._run_named(
                "irreversible_compensation",
                lambda: self._check_irreversible_compensation(manifest),
            )
        )
        return self._report(results)

    def _report(self, results: list[ConformanceCheckResult]) -> ConformanceReport:
        return ConformanceReport(
            adapter_id=str(getattr(self.adapter, "adapter_id", "")),
            adapter_version=str(getattr(self.adapter, "adapter_version", "")),
            checks=tuple(results),
            passed=all(c.passed for c in results),
        )

    def _run_named(self, name: str, fn: CheckFn) -> ConformanceCheckResult:
        try:
            fn()
            return ConformanceCheckResult(name=name, passed=True, detail="ok")
        except AdapterConformanceError as exc:
            return ConformanceCheckResult(name=name, passed=False, detail=str(exc))
        except Exception as exc:  # noqa: BLE001 — conformance must fail closed
            return ConformanceCheckResult(
                name=name,
                passed=False,
                detail=f"unexpected {type(exc).__name__}: {exc}",
            )

    def _check_identity(self) -> None:
        adapter_id = getattr(self.adapter, "adapter_id", None)
        adapter_version = getattr(self.adapter, "adapter_version", None)
        if not isinstance(adapter_id, str) or not adapter_id.strip():
            raise AdapterConformanceError("adapter_id must be a non-empty str")
        if not isinstance(adapter_version, str) or not adapter_version.strip():
            raise AdapterConformanceError("adapter_version must be a non-empty str")
        if len(adapter_id) > 128 or len(adapter_version) > 64:
            raise AdapterConformanceError("adapter identity exceeds length bounds")

    def _assert_prepared(self, manifest: EffectManifest) -> None:
        if not isinstance(manifest, EffectManifest):
            raise AdapterConformanceError("prepare must return EffectManifest")
        if (
            manifest.adapter.adapter_id != self.adapter.adapter_id
            or manifest.adapter.adapter_version != self.adapter.adapter_version
        ):
            raise AdapterConformanceError(
                "prepare returned a manifest whose adapter identity does not "
                "match the executing adapter"
            )
        if not manifest.idempotency_key:
            raise AdapterConformanceError("prepare must set a non-empty idempotency_key")
        if not manifest.effect_type:
            raise AdapterConformanceError("prepare must set a non-empty effect_type")

    def _check_preconditions(self, manifest: EffectManifest) -> None:
        result = self.adapter.validate_preconditions(manifest, self.scenario.context)
        if not isinstance(result, PreconditionResult):
            raise AdapterConformanceError("validate_preconditions must return PreconditionResult")
        if not result.satisfied and not result.reason:
            raise AdapterConformanceError(
                "unsatisfied preconditions must include a non-empty reason"
            )
        if self.scenario.expect_stale_after_mutate:
            if self.scenario.mutate_external_state is None:
                raise AdapterConformanceError(
                    "expect_stale_after_mutate requires mutate_external_state"
                )
            self.scenario.mutate_external_state()
            stale = self.adapter.validate_preconditions(manifest, self.scenario.context)
            if stale.satisfied:
                raise AdapterConformanceError(
                    "validate_preconditions remained satisfied after external "
                    "state mutation (TOCTOU check ineffective)"
                )

    def _check_verify_before_commit(self, manifest: EffectManifest) -> None:
        """Forged CommitResult.success must not become matched_expected before commit."""
        forged = CommitResult(
            success=True,
            idempotency_key=manifest.idempotency_key,
            provider_reference="conformance-forged-ref",
            detail="forged success — must not be trusted alone",
            after_state_digest="sha256:" + ("0" * 64),
        )
        proof = self.adapter.verify(manifest, forged, self.scenario.context)
        if not isinstance(proof, OutcomeProof):
            raise AdapterConformanceError("verify must return OutcomeProof")
        if proof.observed_at.tzinfo is None:
            raise AdapterConformanceError("OutcomeProof.observed_at must be timezone-aware")
        if proof.matched_expected:
            raise AdapterConformanceError(
                "verify returned matched_expected=True for an uncommitted effect "
                "given only a forged CommitResult (violates independent observation)"
            )

    def _check_commit(self, manifest: EffectManifest) -> None:
        grant: Any = self.scenario.grant
        result = self.adapter.commit(manifest, grant, self.scenario.context)
        if not isinstance(result, CommitResult):
            raise AdapterConformanceError("commit must return CommitResult")
        if not result.idempotency_key:
            raise AdapterConformanceError("CommitResult.idempotency_key must be non-empty")
        replay = self.adapter.commit(manifest, grant, self.scenario.context)
        if not isinstance(replay, CommitResult):
            raise AdapterConformanceError("idempotent commit replay must return CommitResult")

    def _check_compensation(self, manifest: EffectManifest) -> None:
        commit_result = CommitResult(
            success=True,
            idempotency_key=manifest.idempotency_key,
            provider_reference="conformance-comp-ref",
        )
        result = self.adapter.compensate(manifest, commit_result, self.scenario.context)
        if not isinstance(result, CompensationResult):
            raise AdapterConformanceError("compensate must return CompensationResult")
        if result.succeeded and not result.attempted:
            raise AdapterConformanceError(
                "CompensationResult cannot have succeeded=True with attempted=False"
            )

    def _check_irreversible_compensation(self, manifest: EffectManifest) -> None:
        if manifest.reversibility != ReversibilityClassification.IRREVERSIBLE:
            return
        commit_result = CommitResult(
            success=True,
            idempotency_key=manifest.idempotency_key,
            provider_reference="conformance-irr-ref",
        )
        result = self.adapter.compensate(manifest, commit_result, self.scenario.context)
        if result.succeeded:
            raise AdapterConformanceError(
                "IRREVERSIBLE effects must never report compensation succeeded=True"
            )


def run_adapter_conformance(
    adapter: EffectAdapter, scenario: ConformanceScenario, *, raise_on_fail: bool = True
) -> ConformanceReport:
    """Convenience entry point used by tests and operator tooling."""
    report = AdapterConformanceKit(adapter=adapter, scenario=scenario).run()
    if raise_on_fail:
        report.raise_if_failed()
    return report


__all__ = [
    "AdapterConformanceKit",
    "ConformanceCheckResult",
    "ConformanceReport",
    "ConformanceScenario",
    "run_adapter_conformance",
]
