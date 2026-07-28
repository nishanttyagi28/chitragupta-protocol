# The Effect Manifest

`chitragupta.domain.manifest.EffectManifest` is the canonical representation
of the exact resolved effect an agent proposes. It is a frozen
(`model_config = ConfigDict(extra="forbid", frozen=True)`) Pydantic v2
model — unknown fields are rejected outright, and once constructed it
cannot be mutated (any attempted assignment raises `ValidationError`).

## Fields

| Field | Type | Purpose |
|---|---|---|
| `schema_version` | `str` | Protocol version; see [protocol-spec.md](protocol-spec.md) |
| `manifest_id` | `str` | Unique identifier for this manifest |
| `effect_type` | `str` | e.g. `"payment.transfer"`, `"email.send"`, `"sqlite.row.update"` |
| `actor` | `Principal` | The agent/service proposing the effect |
| `principal` | `Principal` | The human/service on whose behalf it acts |
| `adapter` | `AdapterIdentity` | Adapter id + version this manifest is bound to |
| `target_resource` | `str` | Exact target (e.g. `"payment:beneficiary/merchant-A"`) |
| `parameters` | `dict[str, str\|int\|bool\|None]` | Canonically normalized, flat, type-restricted |
| `before_state_digest` | `str \| None` | Digest of observed state before the effect |
| `expected_after_state_digest` | `str \| None` | Digest of the expected post-effect state |
| `state_fingerprint` | `StateFingerprint \| None` | The TOCTOU precondition (row version, ETag, etc.) |
| `preconditions` | `tuple[Precondition, ...]` | Additional named preconditions |
| `risk` | `RiskClassification` | `low` / `medium` / `high` / `critical` |
| `reversibility` | `ReversibilityClassification` | `reversible` / `compensatable` / `irreversible` |
| `blast_radius` | `BlastRadiusClassification` | `single_resource` / `bounded_set` / `broad` / `unbounded` |
| `estimated_cost` | `MonetaryAmount \| None` | For cost-bearing effects |
| `idempotency_key` | `str` | Stable across client retries of the same intent |
| `created_at` / `expires_at` | `datetime` (UTC) | Manifest validity window |
| `nonce` | `str` | Prevents hash collisions between logically-identical manifests |
| `parent_manifest_id` | `str \| None` | For delegation-derived manifests |
| `metadata` | `dict[str, str]` | Strictly size-limited (see below); never secrets |

## Why `parameters` is flat and type-restricted

`ParameterValue = str | int | bool | None`. This is a deliberate
restriction, not an oversight: canonicalization and hashing need a
value space with zero ambiguity (no floats — see
[protocol-spec.md](protocol-spec.md)), and adapters that need structured
data (e.g. a list of email recipients) encode it as a sorted,
comma-joined string within the size limits rather than as nested
JSON. This keeps the canonical hash's input space simple to reason about.

## Size and content limits (`config/settings.py`)

- `target_resource`: 1–512 chars, no control characters (`ord(c) < 0x20`
  is rejected — defends against log-injection / control-character
  smuggling in downstream systems that render this string).
- `parameters`: at most 64 keys, keys ≤128 chars, string values ≤4096 chars.
- `metadata`: at most 16 keys, keys ≤64 chars, values ≤512 chars, and
  total serialized size ≤8192 bytes.
- `manifest_id`, `idempotency_key`, `nonce`: 1–128 chars.
- `effect_type`: 1–128 chars.

All of these are enforced by Pydantic field validators and are covered by
adversarial tests (`tests/adversarial/test_malformed_payloads.py`) that
throw oversized/malformed values at every one of them.

## What must never appear in a manifest

Secrets, raw credentials, access tokens, full payment card/account
numbers, or unnecessary personal information. Adapters are responsible for
this: e.g. the email sandbox adapter stores a `body_digest`, never the
raw body, in `parameters`; attachments are digested, never embedded raw
(see `adapters/email_sandbox.py` and
`tests/integration/test_adapter_email_sandbox.py::test_attachments_digested_not_stored_raw`).

## Constructing a manifest

Manifests are built by adapters' `prepare()` methods
(`adapter.prepare(request, context) -> EffectManifest`), never by hand in
application code — this is what guarantees the `state_fingerprint`/
`before_state_digest` are actually populated from a real precondition
check rather than omitted. See [docs/adapter-authoring.md](adapter-authoring.md).
