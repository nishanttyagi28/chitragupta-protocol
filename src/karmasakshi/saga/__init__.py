"""Durable saga orchestration over sealed causal effect graphs (Phase 8).

A saga is multi-step, multi-grant orchestration: each forward step still
requires its own sealed manifest and ExecutionGrant. The saga coordinator
never claims exactly-once execution across providers.
"""

from karmasakshi.saga.machine import (
    assert_can_commit_step,
    assert_can_recover_step,
    mark_compensation_result,
    mark_step_ambiguous,
    mark_step_authorized,
    mark_step_committed,
    mark_step_failed,
    mark_step_verified,
    next_compensation_manifest_hash,
    start_compensation,
)
from karmasakshi.saga.model import (
    MAX_SAGA_STEPS,
    SagaPlan,
    SagaRun,
    SagaRunStatus,
    SagaStepRecord,
    SagaStepStatus,
    build_saga_plan,
    build_saga_run,
)
from karmasakshi.saga.order import topo_manifest_hashes

__all__ = [
    "MAX_SAGA_STEPS",
    "SagaPlan",
    "SagaRun",
    "SagaRunStatus",
    "SagaStepRecord",
    "SagaStepStatus",
    "assert_can_commit_step",
    "assert_can_recover_step",
    "build_saga_plan",
    "build_saga_run",
    "mark_compensation_result",
    "mark_step_ambiguous",
    "mark_step_authorized",
    "mark_step_committed",
    "mark_step_failed",
    "mark_step_verified",
    "next_compensation_manifest_hash",
    "start_compensation",
    "topo_manifest_hashes",
]
