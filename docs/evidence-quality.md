"""Evidence quality and provenance (extreme-v2 Phase 10).

An adapter or provider success response alone is never independent
verification. This phase adds typed ``EvidenceRecord``s with provenance
and freshness so VERIFY/PROVE can fail closed on low-quality or stale
observations.

## Quality ladder (``EvidenceKind``)

1. ``unattributed`` — no honest source
2. ``provider_claim`` — echoed commit/provider success
3. ``adapter_reobserve`` — adapter re-read its system of record
4. ``independent_ledger`` — separate ledger / outbox observation
5. ``witness_attestation`` — Phase 9 witness observation

Default ``EvidencePolicy.min_kind`` is ``adapter_reobserve``.

## Engine

- ``evaluate_evidence`` — dry-run + audit
- ``assert_evidence_quality`` — raise ``EvidenceQualityError`` if not
  acceptable

## Invariants

- **#54** Provider-claim-only evidence cannot satisfy default evidence
  policy (min_kind ≥ adapter_reobserve).
- **#55** Stale evidence (observed_at older than max_age_seconds) fails
  closed.
- **#56** Unattributed evidence and digest/manifest mismatches never
  count; oversized batches raise.
- **#57** Evidence evaluation is deterministic and order-independent.

## Honesty limits

- Adapters are not yet required to emit EvidenceRecords automatically;
  callers wrap OutcomeProof via ``evidence_from_outcome_proof`` with an
  honest kind.
- Sealed evidence-policy bundles deferred (same pattern as witness Phase 9).
"""
