# Execution Grants

`karmasakshi.grants.model.ExecutionGrant` is a signed, scoped, expiring,
revocable, consumable authorization. Like `EffectManifest`, it is frozen
and rejects unknown fields.

## Fields

| Field | Purpose |
|---|---|
| `grant_id` | Unique identifier |
| `manifest_hash` | The exact manifest this grant authorizes execution of. `None` only for a pure delegation/capability grant not yet bound to a concrete effect (see [delegation.md](delegation.md)); a grant actually presented to `engine.commit()` must have this set, and it must equal the sealed manifest's hash exactly (invariant #2) |
| `policy_bundle_hash` | Optional (default `None`, backward compatible). If set, `engine.commit()` requires the exact same signed policy bundle (by hash) to be re-presented and re-verified before the effect executes — see [policy-bundles.md](policy-bundles.md) and invariant #31 |
| `approval_set_hash` | Optional (default `None`, backward compatible). Set only by `engine.authorize_with_quorum()` — a hash over the approving `ApprovalStatement`s that satisfied quorum. Not re-verified at commit time (statements are immutable signed records, unlike a re-editable policy) — see [multi-party-authorization.md](multi-party-authorization.md) and invariant #33 |
| `decision_envelope_hash` | Optional (default `None`, Phase 6). When set by `engine.authorize_with_envelope()`, `commit()` requires the same sealed Decision Envelope (by hash) to be re-presented, re-verified, and to still fit the sealed manifest — see [decision-envelopes.md](decision-envelopes.md) and invariants #39–#40. Mutually exclusive with `causal_graph_hash` |
| `causal_graph_hash` | Optional (default `None`, Phase 6). When set by `engine.authorize_plan()`, `commit()` requires the same sealed causal graph (by hash) and that the sealed manifest is a verified node — see [decision-envelopes.md](decision-envelopes.md) and invariant #41. Mutually exclusive with `decision_envelope_hash` |
| `authority_budget_id` | Optional (default `None`, Phase 12). When set, `commit()` atomically consumes from `EngineContext.budget_ledger` — distinct from `scope.max_amount` — see [authority-budgets.md](authority-budgets.md) and invariants #60–#63 |
| *(no field)* | Separation-of-duty enforcement (`separation_policy_bundle`/`role_assignment` on `authorize()`/`authorize_with_quorum()`) is deliberately **not** bound into any grant field — it is a one-time authorization-time gate, not a re-verified binding. Only the audit trail (`grant.issued`'s `role:<role>` metadata) records that it happened — see [separation-of-duties.md](separation-of-duties.md) and invariant #37 |
| `issuer` | Who authorized this — **must** be `human` or `service`, never `agent` (invariant #30, enforced in `grants/issuer.py`). When issued via `authorize_with_quorum()`, this is the `grant_issuer` (e.g. a "quorum service" identity), distinct from the individual approvers |
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
`KarmaSakshiEngine.authorize()`/`.delegate()` that succeeds with an
agent-typed issuer, and this holds identically whether the call originates
from the CLI, the API, or the LangGraph integration.

## Binding to exactly one manifest

At `commit()` time, the engine requires `grant.manifest_hash ==
sealed.seal.manifest_hash` exactly (string equality of two independently
computed SHA-256 hex digests). A grant approved for manifest A can never
execute manifest B, even if B is byte-for-byte similar — this is invariant
#2 and is the core of what makes KarmaSakshi Protocol's authorization
model different from "the agent may call this tool."
