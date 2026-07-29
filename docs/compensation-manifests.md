# Compensation Manifests and Compensation Passports

Extreme-v2 Phase 7 models compensation as a **separately authorized
effect**, not as a silent rewrite of the original Action Passport.

## Core rules

1. Build a compensation `EffectManifest` with
   `build_compensation_manifest(original=...)`. It always binds
   `parameters["original_manifest_hash"]` (and `original_manifest_id`) so
   those fields participate in `canonical_hash()`.
2. `prepare_compensation` → `seal` → `authorize_compensation` →
   `commit_compensation` (optional `verify` on the compensation effect).
3. Emit a **Compensation Passport** via `build_compensation_passport`.
   This document is independent of the original Action Passport.
4. The original Action Passport may carry *pointers*
   (`compensation_manifest_hash`, `compensation_passport_status`) but
   never has its compensation outcome fields rewritten by the Phase 7
   path as the authoritative record.

## Status triad

| Status | Meaning |
|---|---|
| `refused` | Honestly not attempted (irreversible / unsupported) |
| `attempted` | Compensating effect committed / adapter reported attempt |
| `verified` | Independent observation matched expectation |

An adapter `succeeded=True` alone is never `verified` (invariants #20/#21/#45).

## Execution semantics

`commit_compensation` verifies the compensation grant (bound to the
compensation sealed hash and original binding), then calls
`adapter.compensate(original_manifest, original_commit, ...)`.

It does **not** call `adapter.commit` on the compensation manifest.
Reference adapters reverse effects through `compensate`; a second forward
commit would be the wrong operation. Never claim exactly-once compensation
where the provider cannot support it.

## Legacy path

`engine.compensate()` remains for backward compatibility: it still calls
`adapter.compensate` without a separate sealed grant. Prefer the
authorized compensation path for new work.

## Surfaces

- Library: `karmasakshi.compensation`
- CLI: `karmasakshi compensation prepare|authorize|execute|passport`
  (legacy `karmasakshi compensate` retained)
- API:
  - `POST /manifests/{id}/compensation/prepare`
  - `POST /manifests/{id}/compensation/{cid}/authorize`
  - `POST /manifests/{id}/compensation/{cid}/execute`
  - `GET /manifests/{id}/compensation/{cid}/passport`

## Security invariants

See `#43`–`#45` in [docs/security-model.md](security-model.md).
