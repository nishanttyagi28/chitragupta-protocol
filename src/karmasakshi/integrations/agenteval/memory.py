"""A failure-memory loop over exported AgentEval regression fixtures
(extreme-v2 Phase 25).

Building on the v0.1 AgentEval bridge (`export_regression_fixture` /
`write_fixture`, both unchanged), this adds a durable, portable memory of
previously exported failures: group fixtures by a deterministic **failure
signature** (`effect_type` + `adapter_id` + `failure_category` +
`invariant`) and answer "have we seen a failure shaped like this before,
and how often" -- a summary a caller (an assessment policy, a dashboard,
an alert) can consult.

This is advisory only, same boundary as the Effect Intelligence Engine
(docs/effect-intelligence.md) and the regression-fixture export itself:
it never blocks, auto-classifies, or decides anything on its own. An LLM
or caller may use `FailureMemorySummary` to *explain* "this looks like a
recurring issue", but no security-critical authorization or commit
decision reads from this store.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.errors import FailureMemoryCorruptedError
from karmasakshi.integrations.agenteval.model import RegressionFixture


def failure_signature(fixture: RegressionFixture) -> str:
    """A deterministic grouping key for the *shape* of a failure --
    independent of exact inputs, timestamps, or manifest identity."""
    return failure_signature_for(
        effect_type=fixture.effect_type,
        adapter_id=fixture.adapter_id,
        failure_category=fixture.failure_category,
        invariant=fixture.invariant,
    )


def failure_signature_for(
    *, effect_type: str, adapter_id: str, failure_category: str, invariant: str | None
) -> str:
    return canonical_hash(
        {
            "effect_type": effect_type,
            "adapter_id": adapter_id,
            "failure_category": failure_category,
            "invariant": invariant,
        }
    )


class FailureMemorySummary(BaseModel):
    """How often a given failure shape has been recorded, and when."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signature: str
    effect_type: str
    adapter_id: str
    failure_category: str
    invariant: str | None
    occurrence_count: int
    first_exported_at: datetime
    last_exported_at: datetime


class FailureMemoryStore:
    """Append-only JSON-Lines store of exported `RegressionFixture`s.

    Deliberately unbounded, like an application log: forgetting past
    failures would defeat the point of a *memory*. Callers who need
    rotation/archival should manage the file the same way they would any
    other append-only log -- this store does not truncate or expire
    entries on its own.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def record(self, fixture: RegressionFixture) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(fixture.model_dump_json() + "\n")

    def all_fixtures(self) -> list[RegressionFixture]:
        if not self._path.exists():
            return []
        fixtures: list[RegressionFixture] = []
        for lineno, line in enumerate(self._path.read_text(encoding="utf-8").splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                fixtures.append(RegressionFixture.model_validate_json(line))
            except ValueError as exc:
                raise FailureMemoryCorruptedError(
                    f"{self._path}:{lineno}: not a valid RegressionFixture: {exc}"
                ) from exc
        return fixtures

    def summarize(self) -> list[FailureMemorySummary]:
        """One `FailureMemorySummary` per distinct failure signature,
        ordered by occurrence count (most recurrent first, ties broken by
        signature for determinism)."""
        groups: dict[str, list[RegressionFixture]] = {}
        for fixture in self.all_fixtures():
            groups.setdefault(failure_signature(fixture), []).append(fixture)

        summaries = []
        for signature, fixtures in groups.items():
            ordered = sorted(fixtures, key=lambda f: f.exported_at)
            first, last = ordered[0], ordered[-1]
            summaries.append(
                FailureMemorySummary(
                    signature=signature,
                    effect_type=first.effect_type,
                    adapter_id=first.adapter_id,
                    failure_category=first.failure_category,
                    invariant=first.invariant,
                    occurrence_count=len(fixtures),
                    first_exported_at=first.exported_at,
                    last_exported_at=last.exported_at,
                )
            )
        return sorted(summaries, key=lambda s: (-s.occurrence_count, s.signature))

    def recurrence_count(
        self,
        *,
        effect_type: str,
        adapter_id: str,
        failure_category: str,
        invariant: str | None = None,
    ) -> int:
        """How many times a failure of this exact shape has been recorded."""
        target = failure_signature_for(
            effect_type=effect_type,
            adapter_id=adapter_id,
            failure_category=failure_category,
            invariant=invariant,
        )
        return sum(1 for fixture in self.all_fixtures() if failure_signature(fixture) == target)


__all__ = [
    "FailureMemoryStore",
    "FailureMemorySummary",
    "failure_signature",
    "failure_signature_for",
]
