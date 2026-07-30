# MVP Acceptance Criteria

A commercial MVP is **not claimed** until this checklist passes as an automated end-to-end acceptance test through UI and API.

## Required journey (AI-operated customer refund)

- [x] Organization created
- [x] Authenticated team member
- [x] Refund agent registered
- [x] Payment simulator adapter registered
- [x] Signed organization policy activated
- [x] Exact refund effect proposed
- [x] Risk assessment displayed
- [x] Human approval requested
- [x] Required quorum completed
- [x] Effect committed exactly once through the simulator
- [x] Independent ledger observation
- [x] Action Passport generated (seal/grant/audit signatures verified;
      the Passport's own content hash is not itself a separate signature
      -- see docs/action-passport-v2.md)
- [x] Audit trail searchable
- [x] Modified amount or recipient rejected
- [x] Duplicate retry prevented
- [x] Ambiguous timeout recovered honestly
- [x] Compensation handled as a separate authorized effect
- [x] Cross-tenant access rejected
- [x] Offline passport and audit verification successful

## Status

**Milestone A acceptance passes (25/25).** `karmasakshi-acceptance` drives
25 checks through the real Gateway API, typed SDK, and authenticated UI
(verified locally on 2026-07-30 against a running Gateway).
`tests/integration/test_milestone_a_acceptance.py` repeats the same
journey against a real uvicorn server; the Docker Compose CI job builds
the evaluation image, reruns the command, and publishes its JSON report.

Additional release-critical invariants verified independently after
remediation (not all as separate acceptance checklist rows, but required
for evaluation-ready status):

- Durable refund rehydration across Gateway restart (detail, list,
  Passport, audit, idempotent retry)
- Proposal-time policy binding survives later policy activation and
  process restart
- Per-tenant signing-key durability, cross-tenant isolation, and
  fail-closed behaviour for missing/corrupt/mismatched key material

This is **evaluation-ready self-hosted software**, not a production-
readiness, certification, formal-proof, or real-provider claim. The
payment provider is a simulator and the limitations in
`docs/limitations.md` remain in force.
