# Signed Policy Bundles

Status: **implemented** (extreme-v2 Phase 2). Package: `karmasakshi.policy`.

## What it is

A `PolicyBundle` is a cryptographic envelope around a policy payload —
today, only `IntelligencePolicy.canonical_dict()` (the Effect
Intelligence Engine's scoring rules, see
[docs/effect-intelligence.md](effect-intelligence.md)) — that:

1. Pins the exact policy content in force at a point in time with a
   canonical hash, signed the same way `Seal` pins an `EffectManifest`
   (see `protocol/sealing.py` — `policy/sealing.py` mirrors it exactly).
2. Carries an explicit effective window (`effective_from`/
   `effective_until`) and a `policy_type` discriminator.
3. Can be bound into an `ExecutionGrant` at authorization time
   (`ExecutionGrant.policy_bundle_hash`), so the grant's own signature
   covers *which* policy bundle governed the decision to authorize.
4. Is required again, by hash, at commit time: `engine.commit()` rejects
   a commit if the grant demands a policy bundle and none, or a
   different one, is presented.

This is the mechanism that satisfies the mission requirement "a policy
change after approval must not silently alter an existing authorization":
once a grant is signed with `policy_bundle_hash = H`, no future edit to
the policy can retroactively change what that grant means, because `H`
is cryptographically fixed and `commit()` verifies the exact same
content (not just the same `bundle_id`) is presented again.

## What it is not

- **Not yet an enforcement gate on its own.** Binding a policy bundle
  into a grant does not, by itself, make `EffectAssessment.recommendation`
  block anything -- see [docs/effect-intelligence.md](effect-intelligence.md).
  Phase 2 gives you a cryptographically pinned *reference* to a policy;
  a later phase (M-of-N authorization) is what will make unmet
  requirements (approval counts, witness quorum) structurally block a
  commit.
- **Not multi-tenant-aware in enforcement until Phase 19.** When
  `EngineContext.tenant_id` is set, `PolicyBundle.tenant_id` must match
  (fail closed on uncertainty / mismatch). See
  [docs/multi-tenant.md](multi-tenant.md). Omitting engine tenant_id
  preserves legacy single-tenant behaviour.

## Domain model (`karmasakshi/policy/bundle.py`)

- `PolicyBundle`: `bundle_id`, `bundle_version` (MAJOR.MINOR),
  `policy_type`, `payload` (a plain JSON-safe dict, size-capped at 64KiB
  canonical), `issuer` (a `Principal` -- see invariant below), optional
  `tenant_id`, `created_at`, `effective_from`, optional
  `effective_until`. `canonical_hash()` binds every field.
- `PolicyBundleSeal`: `algorithm`, `key_id`, `bundle_hash`, `signature`,
  `sealed_at` -- structurally identical to `Seal`.
- `SealedPolicyBundle`: `bundle` + `seal`, with `verify_integrity()`
  (tamper detection: recomputed hash vs. sealed hash).

## Sealing and verification (`karmasakshi/policy/sealing.py`)

- `seal_policy_bundle(bundle, signing_key, clock)` -> `SealedPolicyBundle`.
- `verify_policy_bundle(sealed, keyring, now, expected_policy_type=None)`
  performs, in order: integrity check (tamper detection), signature
  verification (identity proof, via `Keyring.verify` -- unknown keys and
  forged signatures both fail closed), optional `policy_type` match, and
  effective-window checks (`PolicyBundleNotYetEffectiveError` /
  `PolicyBundleExpiredError`). Any failure raises a specific
  `PolicyBundleError` subclass -- never a silent `False`.

## Invariant: an agent cannot issue a policy bundle

`build_policy_bundle()` (`karmasakshi/intelligence/policy.py`) rejects an
agent-typed `issuer` with `PolicyBundleIssuerNotAuthorizedError`, mirroring
invariant #30 (`issue_grant()` rejecting an agent issuer). A policy
bundle's thresholds ultimately influence authorization outcomes, so the
same rule applies: an agent may draft policy content, but never be the
principal recorded as authorizing it.

## Binding into `ExecutionGrant` and `engine.commit()`

- `ExecutionGrant.policy_bundle_hash: str | None` (default `None`,
  backward compatible with every existing grant).
- `engine.authorize(..., policy_bundle=sealed)`: verifies `sealed`
  (signature, tamper, effective window) *before* issuing the grant, and
  binds `sealed.seal.bundle_hash` into the grant's own signed payload.
- `engine.commit(..., policy_bundle=sealed)`: if
  `grant.policy_bundle_hash is not None`, the same bundle must be
  re-presented and re-verified, and its hash must exactly equal
  `grant.policy_bundle_hash`. Three distinct failure modes, all fail
  closed with a specific error:
  - `policy_bundle=None` when required -> `PolicyBundleMismatchError`
    ("missing at commit").
  - A validly-signed but *different* bundle presented ->
    `PolicyBundleMismatchError` ("mismatch") -- this is the "policy swap"
    attack the whole feature exists to prevent (see
    `tests/unit/test_engine.py::test_commit_with_swapped_policy_bundle_is_rejected`
    and the CLI/API integration tests).
  - A tampered/expired/forged bundle -> the specific
    `PolicyBundleTamperedError`/`PolicyBundleExpiredError`/
    `InvalidSignatureError`/`UnknownKeyError` propagates through `commit()`.
- A grant issued **without** a policy bundle (`policy_bundle_hash is
  None`, the default) commits exactly as in v0.1 -- this feature is
  purely additive.

## `IntelligencePolicy` <-> `PolicyBundle`

`karmasakshi/intelligence/policy.py`:

- `build_policy_bundle(policy, *, bundle_id, bundle_version, issuer,
  created_at, effective_from, effective_until=None, tenant_id=None)` ->
  `PolicyBundle` with `policy_type="intelligence.v1"` and
  `payload=policy.canonical_dict()`.
- `policy_from_bundle_payload(payload)` -> `IntelligencePolicy`,
  reconstructing a policy object from an already-*verified* bundle's
  payload. Every field is extracted with an explicit type check (not a
  blind cast); a malformed payload raises `ValueError` rather than
  crashing unpredictably or silently substituting a default. Round-trips
  exactly: `policy_from_bundle_payload(build_policy_bundle(p, ...).payload).policy_hash() == p.policy_hash()`
  for any `IntelligencePolicy` (property-tested in
  `tests/property/test_policy_bundle_properties.py`).

## CLI

```text
karmasakshi policy create <bundle_id> --issuer-id ID [--issuer-type human|service]
    [--bundle-version 1.0] [--effective-seconds N] [--tenant-id ID]
    [--block-threshold N] [--review-threshold N] [--max-delegation-depth N]
    [--restricted-effect-type TEXT ...] [--sensitive-target-pattern REGEX ...]
karmasakshi policy sign <bundle_id> --key-id ID
karmasakshi policy verify <bundle_id>

karmasakshi grant issue <manifest_id> ... [--policy-bundle-id ID]
karmasakshi execute <manifest_id> ... [--policy-bundle-id ID]
```

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/policy/bundles` | Build, sign, and store a policy bundle |
| GET | `/policy/bundles/{id}` | Fetch a stored sealed bundle |
| POST | `/policy/bundles/{id}/verify` | Re-verify signature/integrity/window |
| POST | `/manifests/{id}/approve` | Now accepts `policy_bundle_id` |
| POST | `/manifests/{id}/execute` | Now accepts `policy_bundle_id` |

## Known limitations

- `PolicyBundle.payload` shape is validated defensively by
  `policy_from_bundle_payload` but is otherwise an opaque
  `dict[str, object]` at the domain-model level -- only
  `policy_type == "intelligence.v1"` is currently interpretable.
- No key-rotation-aware revocation story for policy bundle signers beyond
  what `Keyring.remove_key` already provides for any signer.
- `tenant_id` is metadata only; see "What it is not" above.
- No UI/CLI listing command for "all policy bundles in this workspace" yet
  (each bundle is addressed by `bundle_id` directly).
