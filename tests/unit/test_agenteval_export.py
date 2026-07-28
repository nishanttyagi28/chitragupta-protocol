from __future__ import annotations

import json

from karmasakshi.adapters.base import CommitResult, OutcomeProof
from karmasakshi.config.clock import FixedClock
from karmasakshi.integrations.agenteval import (
    RegressionFixture,
    export_regression_fixture,
    write_fixture,
)


def test_export_contains_no_secrets_or_raw_credentials(manifest_factory, now):
    manifest = manifest_factory(parameters={"amount": 1000, "currency": "INR"})
    fixture = export_regression_fixture(
        manifest=manifest,
        failure_category="verification_mismatch",
        clock=FixedClock(now),
    )
    serialized = fixture.model_dump_json()
    assert "password" not in serialized.lower()
    assert "secret" not in serialized.lower()
    assert "private_key" not in serialized.lower()


def test_export_captures_expected_vs_observed(manifest_factory, now):
    manifest = manifest_factory()
    commit_result = CommitResult(
        success=True, idempotency_key=manifest.idempotency_key, provider_reference="ref-1"
    )
    outcome_proof = OutcomeProof(
        matched_expected=False, observed_at=now, detail="balance did not change"
    )
    fixture = export_regression_fixture(
        manifest=manifest,
        failure_category="verification_mismatch",
        commit_result=commit_result,
        outcome_proof=outcome_proof,
        invariant="#20 successful API response is not proof",
        clock=FixedClock(now),
    )
    assert fixture.observed_outcome["matched_expected"] is False
    assert fixture.observed_outcome["commit_success"] is True
    assert fixture.invariant == "#20 successful API response is not proof"
    assert fixture.reproduction_metadata["manifest_hash"] == manifest.canonical_hash()


def test_fixture_is_versioned():
    assert RegressionFixture.model_fields["schema_version"].default == "1.0"


def test_write_fixture_roundtrip(tmp_path, manifest_factory, now):
    manifest = manifest_factory()
    fixture = export_regression_fixture(
        manifest=manifest, failure_category="stale_manifest", clock=FixedClock(now)
    )
    path = write_fixture(fixture, tmp_path / "fixtures" / "fixture-1.json")
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    restored = RegressionFixture.model_validate(data)
    assert restored == fixture


def test_normalized_inputs_match_manifest_parameters(manifest_factory, now):
    manifest = manifest_factory(parameters={"amount": 500, "flag": True})
    fixture = export_regression_fixture(
        manifest=manifest, failure_category="commit_failure", clock=FixedClock(now)
    )
    assert fixture.normalized_inputs == {"amount": 500, "flag": True}
