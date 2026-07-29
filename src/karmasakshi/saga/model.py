"""Saga plan and run models (Phase 8)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.causal.graph import CausalEffectGraph
from karmasakshi.compensation.status import CompensationStatus
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.errors import SagaPlanError
from karmasakshi.saga.order import MAX_SAGA_STEPS, topo_manifest_hashes


class SagaRunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_RECOVERY = "awaiting_recovery"
    COMPENSATING = "compensating"
    COMPLETED = "completed"
    FAILED_PARTIAL = "failed_partial"
    ABORTED = "aborted"


class SagaStepStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    AUTHORIZED = "authorized"
    COMMITTING = "committing"
    COMMITTED = "committed"
    VERIFIED = "verified"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    COMPENSATION_REFUSED = "compensation_refused"
    COMPENSATION_FAILED = "compensation_failed"


class SagaStepRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_hash: str
    index: int
    status: SagaStepStatus = SagaStepStatus.PENDING
    grant_id: str | None = None
    commit_success: bool | None = None
    provider_reference: str | None = None
    ambiguous: bool = False
    compensation_status: CompensationStatus | None = None
    detail: str | None = None


class SagaPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    saga_id: str
    causal_graph_hash: str
    step_manifest_hashes: tuple[str, ...]
    created_at: datetime
    nonce: str

    @field_validator("step_manifest_hashes")
    @classmethod
    def _steps(cls, steps: tuple[str, ...]) -> tuple[str, ...]:
        if not steps:
            raise ValueError("saga plan requires at least one step")
        if len(steps) > MAX_SAGA_STEPS:
            raise ValueError(f"saga plan exceeds {MAX_SAGA_STEPS} steps")
        if len(set(steps)) != len(steps):
            raise ValueError("saga step hashes must be unique")
        return steps

    def canonical_hash(self) -> str:
        return canonical_hash(self)


class SagaRun(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    plan: SagaPlan
    status: SagaRunStatus
    steps: tuple[SagaStepRecord, ...]
    cursor: int = 0
    compensation_cursor: int | None = None


def build_saga_plan(
    graph: CausalEffectGraph,
    *,
    saga_id: str | None = None,
    nonce: str | None = None,
    clock: Clock = SYSTEM_CLOCK,
    created_at: datetime | None = None,
) -> SagaPlan:
    """Build a deterministic plan from a verified causal graph's topo order."""
    ordered = topo_manifest_hashes(graph)
    if set(ordered) != set(graph.node_manifest_hashes):
        raise SagaPlanError("saga plan order must cover every graph node exactly once")
    return SagaPlan(
        saga_id=saga_id or str(uuid.uuid4()),
        causal_graph_hash=graph.canonical_hash(),
        step_manifest_hashes=ordered,
        created_at=created_at or clock.now(),
        nonce=nonce or uuid.uuid4().hex,
    )


def build_saga_run(plan: SagaPlan, *, run_id: str | None = None) -> SagaRun:
    steps = tuple(
        SagaStepRecord(
            manifest_hash=manifest_hash,
            index=index,
            status=SagaStepStatus.READY if index == 0 else SagaStepStatus.PENDING,
        )
        for index, manifest_hash in enumerate(plan.step_manifest_hashes)
    )
    return SagaRun(
        run_id=run_id or str(uuid.uuid4()),
        plan=plan,
        status=SagaRunStatus.PENDING,
        steps=steps,
        cursor=0,
    )


__all__ = [
    "MAX_SAGA_STEPS",
    "SagaPlan",
    "SagaRun",
    "SagaRunStatus",
    "SagaStepRecord",
    "SagaStepStatus",
    "build_saga_plan",
    "build_saga_run",
]
