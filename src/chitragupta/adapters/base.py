"""The Effect Adapter contract.

Adapters resolve a raw request into an :class:`EffectManifest`, check
preconditions immediately before commit (TOCTOU protection), perform the
external effect, independently verify the outcome, and -- where honestly
possible -- compensate. Adapters never decide authorization: the engine
always validates a grant before calling ``commit`` (see
docs/adapter-authoring.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from chitragupta.domain.common import StateFingerprint
from chitragupta.domain.manifest import EffectManifest
from chitragupta.grants.model import ExecutionGrant


@dataclass(frozen=True)
class PreconditionResult:
    """Result of re-checking preconditions immediately before commit."""

    satisfied: bool
    reason: str | None = None
    observed_fingerprint: StateFingerprint | None = None


@dataclass(frozen=True)
class CommitResult:
    """Result of performing the external effect."""

    success: bool
    idempotency_key: str
    provider_reference: str | None = None
    detail: str | None = None
    after_state_digest: str | None = None


@dataclass(frozen=True)
class OutcomeProof:
    """Result of independently observing external state after commit."""

    matched_expected: bool
    observed_at: datetime
    observed_after_state_digest: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class CompensationResult:
    """Result of a best-effort compensation attempt.

    ``attempted=False`` (with ``succeeded=False``) means the effect is
    irreversible and compensation was honestly refused, not silently
    skipped -- never report an irreversible action as compensated.
    """

    attempted: bool
    succeeded: bool
    reason: str | None = None
    detail: str | None = None


@runtime_checkable
class EffectAdapter(Protocol):
    """Synchronous effect adapter contract."""

    adapter_id: str
    adapter_version: str

    def prepare(self, request: Any, context: Any) -> EffectManifest: ...

    def validate_preconditions(
        self, manifest: EffectManifest, context: Any
    ) -> PreconditionResult: ...

    def commit(
        self, manifest: EffectManifest, grant: ExecutionGrant, context: Any
    ) -> CommitResult: ...

    def verify(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> OutcomeProof: ...

    def compensate(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> CompensationResult: ...


@runtime_checkable
class AsyncEffectAdapter(Protocol):
    """Asynchronous effect adapter contract -- identical shape, coroutines."""

    adapter_id: str
    adapter_version: str

    async def prepare(self, request: Any, context: Any) -> EffectManifest: ...

    async def validate_preconditions(
        self, manifest: EffectManifest, context: Any
    ) -> PreconditionResult: ...

    async def commit(
        self, manifest: EffectManifest, grant: ExecutionGrant, context: Any
    ) -> CommitResult: ...

    async def verify(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> OutcomeProof: ...

    async def compensate(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> CompensationResult: ...


__all__ = [
    "AsyncEffectAdapter",
    "CommitResult",
    "CompensationResult",
    "EffectAdapter",
    "OutcomeProof",
    "PreconditionResult",
]
