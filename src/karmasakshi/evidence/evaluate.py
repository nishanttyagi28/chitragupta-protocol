"""Deterministic evidence quality evaluation (Phase 10)."""

from __future__ import annotations

from datetime import datetime, timedelta

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.errors import EvidenceBatchTooLargeError
from karmasakshi.evidence.model import (
    EvidenceAssessment,
    EvidenceKind,
    EvidencePolicy,
    EvidenceRecord,
    evidence_kind_rank,
)


def evaluate_evidence_quality(
    records: tuple[EvidenceRecord, ...] | list[EvidenceRecord],
    policy: EvidencePolicy,
    *,
    manifest_hash: str,
    expected_after_state_digest: str | None,
    now: datetime,
) -> EvidenceAssessment:
    """Evaluate evidence set. Pure and order-independent.

    Acceptable iff at least one record survives all fail-closed checks and
    meets ``policy.min_kind``.
    """
    policy_hash = policy.policy_hash()
    if len(records) > policy.max_records_considered:
        raise EvidenceBatchTooLargeError(
            f"received {len(records)} evidence records; "
            f"max_records_considered={policy.max_records_considered}"
        )

    rejections: list[str] = []
    survivors: list[EvidenceRecord] = []
    for rec in records:
        reason = _reject_reason(
            rec,
            policy=policy,
            manifest_hash=manifest_hash,
            expected_after_state_digest=expected_after_state_digest,
            now=now,
        )
        if reason is None:
            survivors.append(rec)
        else:
            rejections.append(f"{rec.evidence_id}:{reason}")

    # Deduplicate by evidence_id keeping latest collected_at
    by_id: dict[str, EvidenceRecord] = {}
    for rec in survivors:
        prev = by_id.get(rec.evidence_id)
        if prev is None or rec.collected_at >= prev.collected_at:
            by_id[rec.evidence_id] = rec
    accepted = sorted(by_id.values(), key=lambda r: (r.kind.value, r.evidence_id))
    strongest: EvidenceKind | None = None
    if accepted:
        strongest = max(accepted, key=lambda r: evidence_kind_rank(r.kind)).kind
    acceptable = strongest is not None and evidence_kind_rank(strongest) >= evidence_kind_rank(
        policy.min_kind
    )
    if not accepted and not rejections:
        rejections.append("no evidence records provided")
    if accepted and not acceptable and strongest is not None:
        rejections.append(
            f"strongest_kind={strongest.value} below min_kind={policy.min_kind.value}"
        )

    evidence_set_hash = None
    accepted_ids = tuple(r.evidence_id for r in accepted)
    if acceptable:
        evidence_set_hash = canonical_hash(
            {
                "manifest_hash": manifest_hash,
                "evidence_policy_hash": policy_hash,
                "digest": expected_after_state_digest,
                "evidence_ids": list(accepted_ids),
                "strongest_kind": strongest.value if strongest else None,
            }
        )
    return EvidenceAssessment(
        acceptable=acceptable,
        evidence_policy_hash=policy_hash,
        evidence_set_hash=evidence_set_hash,
        accepted_evidence_ids=accepted_ids,
        strongest_kind=strongest,
        rejection_reasons=tuple(sorted(rejections)),
    )


def _reject_reason(
    record: EvidenceRecord,
    *,
    policy: EvidencePolicy,
    manifest_hash: str,
    expected_after_state_digest: str | None,
    now: datetime,
) -> str | None:
    if record.manifest_hash != manifest_hash:
        return "manifest_hash mismatch"
    if policy.reject_unattributed and record.kind == EvidenceKind.UNATTRIBUTED:
        return "unattributed evidence rejected"
    if policy.require_source_system and not record.source_system.strip():
        return "source_system required"
    if policy.require_digest:
        if not record.after_state_digest:
            return "after_state_digest required"
        if (
            expected_after_state_digest is not None
            and record.after_state_digest != expected_after_state_digest
        ):
            return "after_state_digest mismatch"
    age = now - record.observed_at
    if age > timedelta(seconds=policy.max_age_seconds):
        return f"stale evidence age={int(age.total_seconds())}s"
    if age < timedelta(0):
        return "observed_at in the future"
    if evidence_kind_rank(record.kind) < evidence_kind_rank(policy.min_kind):
        # Keep for strongest reporting but do not count as survivor for accept?
        # Spec: survivors must meet min_kind individually so strongest of
        # survivors is always >= min_kind when non-empty.
        return f"kind {record.kind.value} below min_kind={policy.min_kind.value}"
    return None


def assert_evidence_quality(
    records: tuple[EvidenceRecord, ...] | list[EvidenceRecord],
    policy: EvidencePolicy,
    *,
    manifest_hash: str,
    expected_after_state_digest: str | None,
    now: datetime,
) -> EvidenceAssessment:
    from karmasakshi.errors import EvidenceQualityError

    result = evaluate_evidence_quality(
        records,
        policy,
        manifest_hash=manifest_hash,
        expected_after_state_digest=expected_after_state_digest,
        now=now,
    )
    if not result.acceptable:
        reasons = "; ".join(result.rejection_reasons) or "evidence not acceptable"
        raise EvidenceQualityError(
            f"evidence quality not acceptable for manifest {manifest_hash}: {reasons}"
        )
    return result


__all__ = ["assert_evidence_quality", "evaluate_evidence_quality"]
