# Execution Grants

`chitragupta.grants.model.ExecutionGrant` is a signed, scoped, expiring,
revocable, consumable authorization. Like `EffectManifest`, it is frozen
and rejects unknown fields.

## Fields

| Field | Purpose |
|---|---|
| `grant_id` | Unique identifier |
| `manifest_hash` | The exact manifest this grant authorizes execution of. `None` only for a pure delegation/capability grant not yet bound to a concrete effect (see [delegation.md](delegation.md)); a grant actually presented to `engine.commit()` must have this set, and it must equal the sealed manifest's hash exactly (invariant #2) |
| `issuer` | Who authorized this — **must** be `human` or `service`, never `agent` (invariant #30, enforced in `grants/issuer.py`) |
| `subject` | Who the grant is issued to (typically the agent) |
| `audience` | Allowed adapter id(s) this grant may be presented to |
| `allowed_effect_types` | Allowed effect type(s) |
| `scope` | `ScopeConstraints` — see [delegation.md](delegation.md) |
| `issued_at` / `not_before` / `expires_at` | Validity window (UTC) |
| `max_uses` | Defaults to 1 |
| `nonce` | Uniqueness |
| `parent_grant_id` | Set when this grant was delegated from a parent |
| `key_id` / `algorithm` / `signature` | Signing metadata |

## Signing and verification

`grants/issuer.py::issue_grant()` builds the grant, computes
`grant.canonical_hash()` (every field except `signature`), and signs those
bytes. `grants/verifier.py` provides three independent checks, composable
as needed:

- `verify_grant_signature(grant, keyring)` — schema version, algorithm,
  and cryptographic signature. Any single field mutation (max_uses,
  manifest_hash, scope, anything) changes the signed payload and makes
  this fail (`InvalidSignatureError`).
- `verify_grant_time_window(grant, now, leeway)` — `not_before - leeway <=
  now <= expires_at + leeway`. Clock-skew leeway is an explicit parameter
  (`ClockSkewPolicy.leeway_seconds`, bounded to ≤300s), never a hidden
  global.
- `verify_grant(grant, keyring, now, leeway)` — both of the above.

These are pure functions with no side effects — they don't check
consumption/revocation, which requires durable state (see
[storage-semantics.md](storage-semantics.md)) and is the engine's job.

## Issuance requires a non-agent issuer

```python
issue_grant(..., issuer=agent_principal, ...)
# raises GrantIssuerNotAuthorizedError
```

This is invariant #30 and is enforced structurally, not by policy
convention — there is no code path in `issue_grant()` or
`ChitraguptaEngine.authorize()`/`.delegate()` that succeeds with an
agent-typed issuer, and this holds identically whether the call originates
from the CLI, the API, or the LangGraph integration.

## Binding to exactly one manifest

At `commit()` time, the engine requires `grant.manifest_hash ==
sealed.seal.manifest_hash` exactly (string equality of two independently
computed SHA-256 hex digests). A grant approved for manifest A can never
execute manifest B, even if B is byte-for-byte similar — this is invariant
#2 and is the core of what makes Chitragupta Protocol's authorization
model different from "the agent may call this tool."
