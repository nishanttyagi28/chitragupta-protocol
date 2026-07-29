"""Unit tests for evidence quality and provenance (Phase 10)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.adapters.base import OutcomeProof
from karmasakshi.config.clock import FixedClock
from karmasakshi.errors import EvidenceBatchTooLargeError, EvidenceQualityError
from karmasakshi.evidence import (
    EvidenceKind,
    EvidencePolicy,
    EvidenceRecord,
    assert_evidence_quality,
    evaluate_evidence_quality,
    evidence_from_outcome_proof,
)

_MH = "sha256:" + "e" * 64
_DIGEST = "digest-ev-1"


def _rec(now, *, kind=EvidenceKind.ADAPTER_REOBSERVE, eid="e1", digest=_DIGEST, age_s=0, mh=_MH):
    observed = now - timedelta(seconds=age_s)
    return EvidenceRecord(
        evidence_id=eid,
        manifest_hash=mh,
        kind=kind,
        source_system="payment.simulator.ledger",
        observation_method="re_read_ledger",
        observed_at=observed,
        collected_at=now,
        after_state_digest=digest,
        matched_expected=True,
    )


def test_adapter_reobserve_accepted(now):
    policy = EvidencePolicy(min_kind=EvidenceKind.ADAPTER_REOBSERVE)
    result = evaluate_evidence_quality(
        [_rec(now)],
        policy,
        manifest_hash=_MH,
        expected_after_state_digest=_DIGEST,
        now=now,
    )
    assert result.acceptable
    assert result.strongest_kind == EvidenceKind.ADAPTER_REOBSERVE
    assert result.evidence_set_hash is not None


def test_provider_claim_rejected_by_default_min_kind(now):
    policy = EvidencePolicy(min_kind=EvidenceKind.ADAPTER_REOBSERVE)
    result = evaluate_evidence_quality(
        [_rec(now, kind=EvidenceKind.PROVIDER_CLAIM)],
        policy,
        manifest_hash=_MH,
        expected_after_state_digest=_DIGEST,
        now=now,
    )
    assert not result.acceptable


def test_stale_evidence_rejected(now):
    policy = EvidencePolicy(max_age_seconds=60)
    result = evaluate_evidence_quality(
        [_rec(now, age_s=120)],
        policy,
        manifest_hash=_MH,
        expected_after_state_digest=_DIGEST,
        now=now,
    )
    assert not result.acceptable
    assert any("stale" in r for r in result.rejection_reasons)


def test_digest_mismatch_rejected(now):
    policy = EvidencePolicy()
    result = evaluate_evidence_quality(
        [_rec(now, digest="other")],
        policy,
        manifest_hash=_MH,
        expected_after_state_digest=_DIGEST,
        now=now,
    )
    assert not result.acceptable


def test_unattributed_rejected(now):
    policy = EvidencePolicy(min_kind=EvidenceKind.UNATTRIBUTED, reject_unattributed=True)
    result = evaluate_evidence_quality(
        [_rec(now, kind=EvidenceKind.UNATTRIBUTED)],
        policy,
        manifest_hash=_MH,
        expected_after_state_digest=_DIGEST,
        now=now,
    )
    assert not result.acceptable


def test_order_independent(now):
    policy = EvidencePolicy(min_kind=EvidenceKind.ADAPTER_REOBSERVE)
    a = _rec(now, eid="a", kind=EvidenceKind.INDEPENDENT_LEDGER)
    b = _rec(now, eid="b", kind=EvidenceKind.ADAPTER_REOBSERVE)
    r1 = evaluate_evidence_quality(
        [a, b], policy, manifest_hash=_MH, expected_after_state_digest=_DIGEST, now=now
    )
    r2 = evaluate_evidence_quality(
        [b, a], policy, manifest_hash=_MH, expected_after_state_digest=_DIGEST, now=now
    )
    assert r1.acceptable and r2.acceptable
    assert r1.evidence_set_hash == r2.evidence_set_hash
    assert r1.strongest_kind == EvidenceKind.INDEPENDENT_LEDGER


def test_batch_too_large(now):
    policy = EvidencePolicy(max_records_considered=1)
    with pytest.raises(EvidenceBatchTooLargeError):
        evaluate_evidence_quality(
            [_rec(now, eid="a"), _rec(now, eid="b")],
            policy,
            manifest_hash=_MH,
            expected_after_state_digest=_DIGEST,
            now=now,
        )


def test_assert_raises(now):
    with pytest.raises(EvidenceQualityError):
        assert_evidence_quality(
            [],
            EvidencePolicy(),
            manifest_hash=_MH,
            expected_after_state_digest=_DIGEST,
            now=now,
        )


def test_evidence_from_outcome_proof(now):
    proof = OutcomeProof(
        matched_expected=True,
        observed_at=now,
        observed_after_state_digest=_DIGEST,
        detail="ok",
    )
    rec = evidence_from_outcome_proof(
        evidence_id="from-proof",
        manifest_hash=_MH,
        proof=proof,
        kind=EvidenceKind.ADAPTER_REOBSERVE,
        source_system="payment.simulator",
        observation_method="verify",
        clock=FixedClock(now),
    )
    assert rec.after_state_digest == _DIGEST
    assert rec.matched_expected is True


def test_engine_assert_evidence(
    engine_factory, manifest_factory, fake_adapter, issuer_signing_key, fixed_clock
):
    engine = engine_factory()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    rec = _rec(fixed_clock.now(), mh=sealed.seal.manifest_hash)
    result = engine.assert_evidence_quality(
        sealed,
        records=[rec],
        policy=EvidencePolicy(),
        expected_after_state_digest=_DIGEST,
    )
    assert result.acceptable
    events = [
        e
        for e in engine._ctx.audit.events_for_manifest(sealed.manifest.manifest_id)
        if e.event_type.startswith("evidence.")
    ]
    assert any(e.event_type == "evidence.quality_asserted" for e in events)
