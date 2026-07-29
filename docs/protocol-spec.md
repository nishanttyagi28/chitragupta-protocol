# Protocol Specification

## Schema versioning

Every `EffectManifest` and `ExecutionGrant` carries a `schema_version`
string of the form `"MAJOR.MINOR"`. A build accepts a manifest/grant only
if `MAJOR` is in `SUPPORTED_MAJOR_VERSIONS` (currently `{"1"}` for
`CURRENT_SCHEMA_VERSION = "1.0"`); `MINOR` differences are tolerated
(reserved for additive, backward-compatible fields). Malformed version
strings (missing dot, non-digit components) and unsupported majors both
raise `SchemaVersionError` — see `protocol/versioning.py`.

## Canonicalization algorithm

Implemented in `canonical/serialize.py`. Given any value built from
`dict`, `list`, `str`, `int`, `bool`, `None`, or a Pydantic model:

1. Pydantic models are converted via `model_dump(mode="json")`.
2. Floats are **rejected** (`CanonicalizationError`) — money and
   fingerprints must be integers (minor units) or strings, never floats,
   to avoid cross-platform float-formatting drift.
3. Dict keys are sorted lexicographically (by raw `str`) at every nesting
   level.
4. The tree is serialized with `json.dumps(..., sort_keys=True,
   separators=(",", ":"), ensure_ascii=True)` — no insignificant
   whitespace, ASCII-safe output regardless of locale.
5. The result is UTF-8 encoded.
6. The canonical hash is `"sha256:" + hexdigest` of those bytes.

Two processes running this exact algorithm over the same logical value
always produce byte-identical output and therefore identical hashes. This
is what cross-process signature verification depends on, and is locked in
by `tests/property/test_cross_process_fixtures.py` (hardcoded expected
hashes) in addition to the internal-consistency property tests.

## What gets hashed

`EffectManifest.canonical_hash()` hashes the *entire* model — every field
participates. There is no separate "security-relevant subset"; changing
any field (target, parameters, nonce, expiry, idempotency key, risk
classification, anything) changes the hash. This is why the manifest has
no self-referential `manifest_hash` field: storing a hash-of-self inside
the object being hashed would require excluding that one field from the
hash computation, which is an unnecessary special case. The hash is always
computed on demand via `.canonical_hash()` and referenced externally (in
the `Seal`, in `ExecutionGrant.manifest_hash`, in audit events, in
passports).

`ExecutionGrant.canonical_hash()` hashes every field **except**
`signature` itself (`signing_payload()` excludes it) — the signature
covers everything else, including `manifest_hash`, `audience`,
`allowed_effect_types`, `scope`, the time window, and `max_uses`.

## Sealing

`protocol/sealing.py`:

- `seal_manifest(manifest, signing_key, clock)` computes
  `manifest.canonical_hash()`, signs those bytes, and returns a
  `SealedManifest(manifest, seal)` where `seal.manifest_hash` is the hash
  that was signed.
- `verify_seal(sealed, keyring)` does two independent checks:
  1. `sealed.verify_integrity()` recomputes the hash and compares it to
     `seal.manifest_hash` (tamper detection — catches *any* field mutation
     after sealing).
  2. `keyring.verify(seal.key_id, seal.manifest_hash, seal.signature)`
     (cryptographic identity proof — catches a forged/replaced signature
     even when the manifest content and hash are untouched).

Both checks are mandatory at every point a `SealedManifest` is consumed,
including at `commit()` time, not just at `authorize()` time — see the
git history around `engine.commit()` for why this distinction matters (a
forged-signature-with-unchanged-content regression test exists precisely
because an earlier version only re-checked #1, not #2, at commit time).

## Policy bundle sealing

`policy/sealing.py` (extreme-v2 Phase 2) applies the identical
two-check pattern above to `PolicyBundle`/`SealedPolicyBundle` instead of
`EffectManifest`/`SealedManifest`: `seal_policy_bundle()` signs
`bundle.canonical_hash()`; `verify_policy_bundle()` recomputes the hash
(tamper detection) and checks the signature (identity proof), plus an
effective-window check specific to policy bundles. See
[docs/policy-bundles.md](policy-bundles.md).

## Nonces and idempotency keys

- `nonce` exists purely to make otherwise-identical manifests hash
  differently (defense against hash collisions/replay of a logically
  identical but distinct proposal).
- `idempotency_key` is the caller's stable identifier for "this exact
  real-world intent," and is what the engine's idempotency ledger keys on
  for exactly-once execution across retries (see
  [docs/crash-recovery.md](crash-recovery.md)). It is expected to be
  stable across a client-side retry of the whole pipeline, even though the
  manifest's `manifest_id` and `nonce` will differ between the original
  attempt and the retry.
