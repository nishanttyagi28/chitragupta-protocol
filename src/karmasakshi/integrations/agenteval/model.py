"""A versioned, neutral regression-fixture export format.

This is **not** a claim of compatibility with any specific AgentEval schema
-- the exact upstream format was not confirmed at the time this was
written. What's implemented is a documented, stable boundary: a
self-describing JSON fixture containing only redacted, reproducible
information, versioned independently so a real AgentEval adapter can be
layered on top later without this module changing (see
docs/agenteval-integration.md).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from karmasakshi.domain.manifest import ParameterValue

FIXTURE_SCHEMA_VERSION = "1.0"


class RegressionFixture(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = FIXTURE_SCHEMA_VERSION
    exported_at: datetime

    effect_type: str
    adapter_id: str
    adapter_version: str

    normalized_inputs: dict[str, ParameterValue]
    expected_effect: dict[str, str | None]
    observed_outcome: dict[str, str | bool | None]

    failure_category: str
    invariant: str | None = None
    reproduction_metadata: dict[str, str]


__all__ = ["FIXTURE_SCHEMA_VERSION", "RegressionFixture"]
