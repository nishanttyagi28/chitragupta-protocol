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
- [x] Signed Action Passport generated
- [x] Audit trail searchable
- [x] Modified amount or recipient rejected
- [x] Duplicate retry prevented
- [x] Ambiguous timeout recovered honestly
- [x] Compensation handled as a separate authorized effect
- [x] Cross-tenant access rejected
- [x] Offline passport and audit verification successful

## Status

**Milestone A acceptance passes.** `karmasakshi-acceptance` drives 25
checks through the real Gateway API, typed SDK, and authenticated UI.
`tests/integration/test_milestone_a_acceptance.py` repeats the same
journey against a real uvicorn server; the Docker Compose CI job builds
the evaluation image, reruns the command, and publishes its JSON report.

This is an evaluation milestone, not a production-readiness or
certification claim. The provider is a simulator and the limitations in
`docs/limitations.md` remain in force.
