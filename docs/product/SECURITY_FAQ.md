# Security FAQ (Draft)

## Is KarmaSakshi an IAM product?

No. It seals and witnesses **consequential effects**, not login sessions.

## Does a successful adapter response prove the outcome?

No. `VERIFY` requires independent observation (invariants #20/#21).

## Can an agent authorize itself?

No. Agent principals cannot issue grants, policy bundles, decision envelopes,
or approval statements (invariant #30 and related).

## Is compensation guaranteed rollback?

No. Compensation is best-effort and separately authorized (Phase 7). Refused
compensation is reported honestly.

## Do you support Stripe / AWS KMS / HSM today?

Not as production connectors. Interfaces and deterministic emulators may
exist; do not claim live provider support until conformance tests and
credentials are real.

## Is the system formally verified / certified?

No. Invariants are tested, not theorem-proved. No SOC 2/ISO claim.
