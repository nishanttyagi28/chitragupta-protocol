"""Pure saga run/step transition helpers (fail closed)."""

from __future__ import annotations

from karmasakshi.compensation.status import CompensationStatus
from karmasakshi.errors import SagaAmbiguousStepError, SagaIllegalTransitionError
from karmasakshi.saga.model import (
    SagaRun,
    SagaRunStatus,
    SagaStepRecord,
    SagaStepStatus,
)


def _replace_step(run: SagaRun, index: int, step: SagaStepRecord) -> SagaRun:
    steps = list(run.steps)
    steps[index] = step
    return run.model_copy(update={"steps": tuple(steps)})


def assert_can_commit_step(run: SagaRun, manifest_hash: str) -> int:
    """Return the step index that may be committed, or raise."""
    if run.cursor < 0 or run.cursor >= len(run.steps):
        raise SagaIllegalTransitionError(f"saga run {run.run_id} has no forward cursor")
    step = run.steps[run.cursor]
    if step.manifest_hash != manifest_hash:
        raise SagaIllegalTransitionError(
            f"saga cursor expects {step.manifest_hash}, got {manifest_hash}"
        )
    if step.status == SagaStepStatus.AMBIGUOUS or step.ambiguous:
        raise SagaAmbiguousStepError(
            f"saga step {manifest_hash} is AMBIGUOUS; recover before any re-commit"
        )
    if run.status in {
        SagaRunStatus.AWAITING_RECOVERY,
        SagaRunStatus.COMPENSATING,
        SagaRunStatus.COMPLETED,
        SagaRunStatus.FAILED_PARTIAL,
        SagaRunStatus.ABORTED,
    }:
        raise SagaIllegalTransitionError(
            f"saga run {run.run_id} status {run.status.value} cannot accept commits"
        )
    if step.status not in {SagaStepStatus.AUTHORIZED}:
        raise SagaIllegalTransitionError(
            f"saga step {manifest_hash} status {step.status.value} cannot be committed"
        )
    return run.cursor


def assert_can_recover_step(run: SagaRun, manifest_hash: str) -> int:
    if run.status != SagaRunStatus.AWAITING_RECOVERY:
        raise SagaIllegalTransitionError(
            f"saga run {run.run_id} is not awaiting recovery ({run.status.value})"
        )
    for step in run.steps:
        if step.manifest_hash == manifest_hash:
            if step.status != SagaStepStatus.AMBIGUOUS:
                raise SagaIllegalTransitionError(f"saga step {manifest_hash} is not AMBIGUOUS")
            return step.index
    raise SagaIllegalTransitionError(f"manifest {manifest_hash} is not a step in this saga")


def mark_step_authorized(run: SagaRun, manifest_hash: str, grant_id: str) -> SagaRun:
    if run.cursor >= len(run.steps):
        raise SagaIllegalTransitionError("no step available to authorize")
    step = run.steps[run.cursor]
    if step.manifest_hash != manifest_hash:
        raise SagaIllegalTransitionError(
            f"saga cursor expects {step.manifest_hash}, got {manifest_hash}"
        )
    if step.status not in {SagaStepStatus.READY, SagaStepStatus.PENDING}:
        raise SagaIllegalTransitionError(
            f"saga step {manifest_hash} status {step.status.value} cannot be authorized"
        )
    updated = _replace_step(
        run,
        step.index,
        step.model_copy(update={"status": SagaStepStatus.AUTHORIZED, "grant_id": grant_id}),
    )
    return updated.model_copy(update={"status": SagaRunStatus.RUNNING})


def mark_step_committed(
    run: SagaRun,
    manifest_hash: str,
    *,
    success: bool,
    provider_reference: str | None,
    detail: str | None = None,
) -> SagaRun:
    index = assert_can_commit_step(run, manifest_hash)
    step = run.steps[index]
    if not success:
        return mark_step_failed(run, manifest_hash, detail=detail)
    updated = _replace_step(
        run,
        index,
        step.model_copy(
            update={
                "status": SagaStepStatus.COMMITTED,
                "commit_success": True,
                "provider_reference": provider_reference,
                "detail": detail,
            }
        ),
    )
    return updated.model_copy(update={"status": SagaRunStatus.RUNNING})


def mark_step_verified(run: SagaRun, manifest_hash: str) -> SagaRun:
    step = next((s for s in run.steps if s.manifest_hash == manifest_hash), None)
    if step is None:
        raise SagaIllegalTransitionError(f"manifest {manifest_hash} is not a step in this saga")
    if step.status != SagaStepStatus.COMMITTED:
        raise SagaIllegalTransitionError(
            f"saga step {manifest_hash} must be COMMITTED before VERIFIED"
        )
    updated = _replace_step(
        run, step.index, step.model_copy(update={"status": SagaStepStatus.VERIFIED})
    )
    next_cursor = step.index + 1
    if next_cursor >= len(run.steps):
        return updated.model_copy(update={"cursor": next_cursor, "status": SagaRunStatus.COMPLETED})
    next_step = updated.steps[next_cursor]
    updated = _replace_step(
        updated,
        next_cursor,
        next_step.model_copy(update={"status": SagaStepStatus.READY}),
    )
    return updated.model_copy(update={"cursor": next_cursor, "status": SagaRunStatus.RUNNING})


def mark_step_ambiguous(run: SagaRun, manifest_hash: str, *, detail: str | None = None) -> SagaRun:
    index = assert_can_commit_step(run, manifest_hash)
    step = run.steps[index]
    updated = _replace_step(
        run,
        index,
        step.model_copy(
            update={
                "status": SagaStepStatus.AMBIGUOUS,
                "ambiguous": True,
                "detail": detail,
            }
        ),
    )
    return updated.model_copy(update={"status": SagaRunStatus.AWAITING_RECOVERY})


def mark_step_failed(run: SagaRun, manifest_hash: str, *, detail: str | None = None) -> SagaRun:
    step = next((s for s in run.steps if s.manifest_hash == manifest_hash), None)
    if step is None:
        raise SagaIllegalTransitionError(f"manifest {manifest_hash} is not a step in this saga")
    updated = _replace_step(
        run,
        step.index,
        step.model_copy(
            update={
                "status": SagaStepStatus.FAILED,
                "commit_success": False,
                "detail": detail,
            }
        ),
    )
    return start_compensation(updated)


def start_compensation(run: SagaRun) -> SagaRun:
    """Enter compensating mode; cursor walks reverse over committed/verified steps."""
    committed_indices = [
        s.index
        for s in run.steps
        if s.status in {SagaStepStatus.COMMITTED, SagaStepStatus.VERIFIED}
    ]
    if not committed_indices:
        return run.model_copy(update={"status": SagaRunStatus.ABORTED})
    return run.model_copy(
        update={
            "status": SagaRunStatus.COMPENSATING,
            "compensation_cursor": max(committed_indices),
        }
    )


def mark_compensation_result(
    run: SagaRun,
    manifest_hash: str,
    status: CompensationStatus,
    *,
    detail: str | None = None,
) -> SagaRun:
    if run.status != SagaRunStatus.COMPENSATING:
        raise SagaIllegalTransitionError("saga is not compensating")
    step = next((s for s in run.steps if s.manifest_hash == manifest_hash), None)
    if step is None:
        raise SagaIllegalTransitionError(f"manifest {manifest_hash} is not a step in this saga")
    if run.compensation_cursor != step.index:
        raise SagaIllegalTransitionError(
            f"compensation cursor expects index {run.compensation_cursor}, got {step.index}"
        )
    if status == CompensationStatus.VERIFIED:
        step_status = SagaStepStatus.COMPENSATED
    elif status == CompensationStatus.REFUSED:
        step_status = SagaStepStatus.COMPENSATION_REFUSED
    else:
        step_status = SagaStepStatus.COMPENSATION_FAILED
    updated = _replace_step(
        run,
        step.index,
        step.model_copy(
            update={
                "status": step_status,
                "compensation_status": status,
                "detail": detail,
            }
        ),
    )
    remaining = [
        s.index
        for s in updated.steps
        if s.index < step.index and s.status in {SagaStepStatus.COMMITTED, SagaStepStatus.VERIFIED}
    ]
    if not remaining:
        refused_or_failed = any(
            s.status
            in {
                SagaStepStatus.COMPENSATION_REFUSED,
                SagaStepStatus.COMPENSATION_FAILED,
            }
            for s in updated.steps
        )
        # Always FAILED_PARTIAL after compensation: saga never claims full atomic rollback.
        _ = refused_or_failed
        return updated.model_copy(
            update={"status": SagaRunStatus.FAILED_PARTIAL, "compensation_cursor": None}
        )
    return updated.model_copy(update={"compensation_cursor": max(remaining)})


def next_compensation_manifest_hash(run: SagaRun) -> str | None:
    if run.status != SagaRunStatus.COMPENSATING or run.compensation_cursor is None:
        return None
    return run.steps[run.compensation_cursor].manifest_hash


__all__ = [
    "assert_can_commit_step",
    "assert_can_recover_step",
    "mark_compensation_result",
    "mark_step_ambiguous",
    "mark_step_authorized",
    "mark_step_committed",
    "mark_step_failed",
    "mark_step_verified",
    "next_compensation_manifest_hash",
    "start_compensation",
]
