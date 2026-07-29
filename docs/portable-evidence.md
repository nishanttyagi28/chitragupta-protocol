# Portable Evidence Packs

Extreme-v2 **Phase 24** introduces `karmasakshi.portable`: a self-contained,
offline-verifiable **Evidence Pack** (`evidence_pack.v1`, schema `1.0`) for
one manifest.

## What's in a pack

| Field | Content |
|---|---|
| `passport` | The Action Passport V2 (`ActionPassportV2`) for this manifest |
| `sealed_manifest` | The full `SealedManifest` (manifest + seal) |
| `grant` | The `ExecutionGrant`, if one was issued |
| `audit_events` | This manifest's audit event slice (`AuditJournal.events_for_manifest`) |
| `verification_keys` | Public keys only, copied out of the keyring in use at build time |
| `pack_hash` | Canonical hash of the whole payload (excluding `generated_at`) |

A recipient with only this one JSON document — no access to the original
store, database, or live keyring — can independently redo every check the
issuing system made:

- `pack_hash` — was the bundle altered in transit or at rest?
- `passport.verify_passport_hash()` — was the passport content altered?
- the seal (`karmasakshi.protocol.sealing.verify_seal`) — using only the
  embedded public keys
- the grant signature (`karmasakshi.grants.verifier.verify_grant_signature`),
  if a grant is present
- the audit event slice's self-consistency
  (`karmasakshi.audit.journal.verify_event_self_consistency`)
- cross-consistency: the sealed manifest, passport, and grant (if any)
  all reference the same manifest hash; every embedded audit event's
  `manifest_id` matches the pack's `manifest_id`

None of this is a new cryptographic primitive — every check already exists
elsewhere in the protocol. What's new is packaging their inputs into one
portable, versioned artifact.

## Usage

```python
from karmasakshi.portable import build_evidence_pack, verify_evidence_pack

pack = build_evidence_pack(
    passport=passport_v2,
    sealed_manifest=sealed,
    audit=engine.context.audit,
    keyring=engine.context.keyring,
    grant=grant,  # optional
)

result = verify_evidence_pack(pack)  # fully offline -- no live state consulted
assert result.all_verified
```

## Surfaces

- CLI: `karmasakshi evidence-pack build <manifest-id> [--grant-id ...] [-o file]`,
  `karmasakshi evidence-pack verify <pack-file>` (the latter reads only the
  file; no workspace keys or stores are touched)
- API: `GET /passports/{manifest_id}/evidence-pack` (authenticated, builds
  from server state), `POST /evidence-pack/verify` (deliberately
  **unauthenticated** — a recipient with no account on the issuing
  deployment can still verify a pack they were handed, the same way
  anyone can check a signature without an account)

## Audit chain verification: full journal vs. one manifest's slice

`AuditJournal.verify_chain()` (existing, unchanged) verifies a *complete*
hash chain from sequence 1 with no gaps — that only holds for the entire
journal. A pack embeds `events_for_manifest(manifest_id)`, a slice
filtered out of a *shared* journal: other manifests' events sit between
this manifest's own events in the real chain, so a from-genesis chain
check would not (and should not be expected to) hold over the filtered
slice alone.

`verify_event_self_consistency()` is the honest, weaker guarantee actually
available to a filtered slice: every embedded event's own hash is
untampered, and sequence numbers are strictly increasing (no reordering,
no duplication). It does **not** prove the slice is complete, or that
nothing was tampered with elsewhere in the full journal (events for other
manifests aren't present to check against).

## Known limitations

- **Offline verification proves internal consistency, not provenance.**
  An adversary who controls key generation can produce a wholly
  self-consistent, self-signed pack (real seal, real signature, real
  hash chain over its own fabricated audit trail) that passes every
  check above — because every check is *internal* to the pack. Nothing
  here proves a particular organization actually issued it, or that the
  manifest was ever authorized or committed against a real system.
  Recipients who need that must independently, separately obtain the
  issuer's trusted `key_id`s (e.g. from a prior out-of-band exchange) and
  cross-check them against `verification_keys`, rather than trusting
  whatever keys happen to be embedded in the pack.
  See `tests/adversarial/test_portable_evidence_gaming.py::test_offline_verification_does_not_prove_the_pack_reflects_a_real_deployment`.
- **A revoked key still verifies.** `verification_keys` is a snapshot of
  the keyring at build time; a key revoked afterward is not re-checked
  against current trust status by `verify_evidence_pack` alone.
- **Bounded, not unlimited.** A pack embeds at most 10,000 audit events
  and 256 verification keys (`MAX_EMBEDDED_AUDIT_EVENTS` /
  `MAX_EMBEDDED_KEYS`); building a pack for a manifest whose audit slice
  or active keyring exceeds those ceilings raises
  `EvidencePackTooLargeError` rather than silently truncating.
- **Not a substitute for `docs/action-passport-v2.md` or the audit
  journal.** It packages copies of both for portability; the live audit
  journal remains the authoritative append-only record.
