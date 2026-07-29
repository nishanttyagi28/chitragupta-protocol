"""Adversarial tests for evidence quality (Phase 10)."""

from __future__ import annotations

from datetime import timedelta

from karmasakshi.evidence import (
    EvidenceKind,
    EvidencePolicy,
    EvidenceRecord,
    evaluate_evidence_quality,
)

_MH = "sha256:" + "f" * 64


def test_cannot_upgrade_provider_claim_by_relabeling_without_meeting_min_kind(now):
    """A PROVIDER_CLAIM record cannot satisfy a policy requiring ADAPTER_REOBSERVE."""
    policy = EvidencePolicy(min_kind=EvidenceKind.ADAPTER_REOBSERVE)
    rec = EvidenceRecord(
        evidence_id="claim",
        manifest_hash=_MH,
        kind=EvidenceKind.PROVIDER_CLAIM,
        source_system="provider.api",
        observation_method="trust_commit_response",
        observed_at=now,
        collected_at=now,
        after_state_digest="d",
        matched_expected=True,
    )
    result = evaluate_evidence_quality(
        [rec], policy, manifest_hash=_MH, expected_after_state_digest="d", now=now
    )
    assert not result.acceptable


def test_swapped_manifest_hash_never_counts(now):
    policy = EvidencePolicy()
    rec = EvidenceRecord(
        evidence_id="x",
        manifest_hash="sha256:" + "0" * 64,
        kind=EvidenceKind.INDEPENDENT_LEDGER,
        source_system="ledger",
        observation_method="read",
        observed_at=now,
        collected_at=now,
        after_state_digest="d",
        matched_expected=True,
    )
    result = evaluate_evidence_quality(
        [rec], policy, manifest_hash=_MH, expected_after_state_digest="d", now=now
    )
    assert not result.acceptable


def test_future_dated_observation_rejected(now):
    policy = EvidencePolicy()
    future = now + timedelta(hours=1)
    rec = EvidenceRecord(
        evidence_id="future",
        manifest_hash=_MH,
        kind=EvidenceKind.ADAPTER_REOBSERVE,
        source_system="ledger",
        observation_method="read",
        observed_at=future,
        collected_at=future,
        after_state_digest="d",
        matched_expected=True,
    )
    result = evaluate_evidence_quality(
        [rec], policy, manifest_hash=_MH, expected_after_state_digest="d", now=now
    )
    assert not result.acceptable
