# Action Passports

`karmasakshi.passports.build_passport(...)` assembles a complete, factual
record of one effect's lifecycle — the "PROVE" step. It deliberately
excludes chain-of-thought or any free-form model reasoning: only
structured facts.

## Fields (`ActionPassport`)

- **What was proposed / the exact approved effect**: `manifest_id`,
  `manifest_hash`, `effect_type`, `actor`, `principal`, `target_resource`,
  `proposed_parameters`, `risk`, `reversibility`.
- **Who/what authorized it, and when it was valid**: `grant_id`,
  `authorized_by`, `authorization_valid_from`/`_until`,
  `authorization_policy_bundle_hash`, `authorization_approval_set_hash`,
  `was_revoked`, `role_participation` (separation-of-duty role facts,
  e.g. `{"proposer": "agent-1", "approver": "user-a,user-b"}` --
  populated automatically from the audit trail, `None` if no grant was
  issued; see [separation-of-duties.md](separation-of-duties.md)).
- **What was executed**: `commit_attempted`, `commit_success`,
  `provider_reference`, `commit_detail`.
- **What was observed afterward**: `observed_matched_expected`,
  `observed_after_state_digest`, `observation_detail`.
- **Compensation**: `compensation_attempted`, `compensation_succeeded`,
  `compensation_reason`.
- **Causal effect graph** (advisory, extreme-v2 Phase 5): `causal_ancestor_hashes`
  (every manifest hash this one causally descends from, transitively),
  `causal_graph_verified` (signatures + no cycle), `causal_graph_reason`
  -- populated only if a `CausalEffectGraph` was explicitly passed to
  `build_passport()`; see [causal-effect-graphs.md](causal-effect-graphs.md).
- **Cryptographic verification status**: `PassportVerificationStatus` —
  `seal_verified`, `grant_verified`, `audit_chain_verified`, plus a detail
  string when any of them failed.

`build_passport()` performs these verifications itself at generation time
— it doesn't just copy a stored "verified: true" flag. A tampered manifest
passed to `build_passport()` produces a passport with
`verification.seal_verified == False`, not a passport that silently omits
the problem (see `test_passport_detects_tampered_manifest`).

## Generating one

```python
from karmasakshi.passports import build_passport, render_passport_markdown

passport = build_passport(
    sealed=sealed_manifest,
    keyring=engine.context.keyring,
    audit=engine.context.audit,
    lifecycle_state=engine.get_lifecycle_state(manifest_id).value,
    grant=grant,  # optional
    grant_store=engine.context.grant_store,  # optional, needed for was_revoked
    commit_result=commit_result,  # optional
    outcome_proof=outcome_proof,  # optional
    compensation_result=compensation_result,  # optional
)
print(render_passport_markdown(passport))
```

Any of the optional arguments can be omitted — a passport generated right
after `seal()` (before authorization even happens) is valid and honestly
shows `grant_id=None`, `commit_attempted=False`.

## Output formats

- `passport.model_dump_json()` — JSON.
- `render_passport_markdown(passport)` — human-readable Markdown, always
  ending with an explicit "this passport is a factual record, not a
  security certification" line.
- `render_passport_html(passport)` — the Markdown wrapped in an escaped
  `<pre>` block (no HTML injection risk from manifest content).

## Where you can get one

- CLI: `karmasakshi passport <manifest-id> [--format json|markdown|html] [--grant-id ...] [-o file]`
- API: `GET /passports/{manifest_id}?fmt=json|markdown|html`
