# Action Passport V2

Extreme-v2 **Phase 23** introduces a versioned Action Passport schema
(`action_passport.v2`, schema `2.0`) alongside the unchanged v1
`ActionPassport`.

## What V2 adds

| Field | Purpose |
|---|---|
| `passport_format` | Always `action_passport.v2` |
| `schema_version` | Always `2.0` (rejects other values) |
| `outcome_status` | Deterministic high-level outcome enum derived from structured facts |
| `passport_hash` | Canonical hash of the payload excluding `generated_at` |
| `tenant_id` | Optional tenant binding when multi-tenant context is present |

V2 does **not** invent new cryptography, claim certification, or replace
v1. Default CLI/API passport emission remains v1.

## Outcome status (honest mapping)

`derive_outcome_status()` maps v1 facts deterministically. Priority order
(high → low):

1. `revoked` — grant revoked or lifecycle `revoked`
2. `failed` — lifecycle failed, or commit failed without verification
3. `compensation_verified` / `compensation_attempted`
4. `ambiguous` — commit detail mentions ambiguity
5. `verified_match` / `verified_mismatch` — independent observation only
6. `committed_unverified` — executor reported success without observation
7. `authorized_not_committed` — grant present, commit not attempted
8. `unknown` — otherwise

**Invariant #73:** Executor `CommitResult.success` alone never yields
`verified_match`. Independent observation (`observed_matched_expected`)
is required.

## Building and verifying

```python
from karmasakshi.passports import build_passport_v2

passport = build_passport_v2(
    sealed=sealed,
    keyring=keyring,
    audit=audit,
    lifecycle_state=state,
    grant=grant,
    commit_result=commit_result,
    outcome_proof=outcome_proof,
    tenant_id="org-a",  # optional
)
passport.verify_passport_hash()  # raises ManifestTamperedError on tamper
```

Upgrade path:

```python
from karmasakshi.passports import build_passport, upgrade_passport_v1_to_v2

v2 = upgrade_passport_v1_to_v2(build_passport(...), tenant_id="org-a")
```

## Surfaces

- Library: `build_passport_v2`, `ActionPassportV2`, `OutcomeStatus`
- CLI: `karmasakshi passport <id> --version v2`
- API: `GET /passports/{id}?version=v2&fmt=json|markdown|html`

## Limitations

- `passport_hash` binds structured passport content; it is not a
  separately signed credential (seal/grant/audit verification remain
  the cryptographic anchors).
- V2 is not a portable evidence pack for third-party observability
  products (Phase 24).
- Offline verification of seal/grant/audit still requires the keyring
  and audit chain, as with v1.
