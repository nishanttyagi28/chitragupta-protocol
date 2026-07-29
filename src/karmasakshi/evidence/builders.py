"""Helpers to build attributed evidence from OutcomeProof (Phase 10)."""

from __future__ import annotations

from karmasakshi.adapters.base import OutcomeProof
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.evidence.model import EvidenceKind, EvidenceRecord


def evidence_from_outcome_proof(
    *,
    evidence_id: str,
    manifest_hash: str,
    proof: OutcomeProof,
    kind: EvidenceKind,
    source_system: str,
    observation_method: str,
    source_principal_id: str | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> EvidenceRecord:
    """Wrap an OutcomeProof as an attributed EvidenceRecord.

    Callers must choose an honest ``kind``: claiming ``INDEPENDENT_LEDGER``
    for a pure provider success echo is a protocol misuse and will be
    rejected by policies that require ``ADAPTER_REOBSERVE`` or stronger.
    """
    collected = clock.now()
    return EvidenceRecord(
        evidence_id=evidence_id,
        manifest_hash=manifest_hash,
        kind=kind,
        source_system=source_system,
        observation_method=observation_method,
        observed_at=proof.observed_at,
        collected_at=collected if collected >= proof.observed_at else proof.observed_at,
        after_state_digest=proof.observed_after_state_digest,
        matched_expected=proof.matched_expected,
        source_principal_id=source_principal_id,
        detail=proof.detail,
    )


__all__ = ["evidence_from_outcome_proof"]
