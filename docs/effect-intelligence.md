# Effect Intelligence Engine

Status: **implemented, advisory-only** (extreme-v2 Phase 1). Package:
`karmasakshi.intelligence`.

## What it is

A deterministic risk-scoring engine that assesses a proposed
`EffectManifest` against a versioned `IntelligencePolicy` and a set of
explicit `AssessmentFacts`, producing a structured `EffectAssessment`.

It is a pure function of those three inputs: no randomness, no network
calls, no LLM in the loop at all. Every signal is a named rule over
manifest fields, policy thresholds, or supplied facts (see
`karmasakshi/intelligence/engine.py`). This satisfies operating rule #8
("LLMs may assist with explanations or anomaly suggestions only") in its
strongest form -- there is no model to exclude from the decision, because
no model is present.

## What it is not (yet)

**The recommendation is advisory.** `engine.authorize()` and
`engine.commit()` do not read or enforce `EffectAssessment.recommendation`
in this protocol version. Nothing in the engine currently turns a `BLOCK`
recommendation into a denied authorization. Binding an assessment's
`policy_hash` into the authorization/commit path so a `BLOCK` (or an
unmet `required_human_approvals`/`required_witness_quorum`) is
structurally enforced is the job of signed policy bundles and M-of-N
authorization -- later phases of this program, not yet implemented.

Treat `karmasakshi assess` / `POST /manifests/{id}/assess` today as: run
the deterministic scorer, get a structured, auditable answer, and decide
what to do with it yourself (feed it to a human reviewer, a policy
service, or your own gating logic in the calling application).

## Inputs

### `EffectManifest`

Read directly: `risk`, `reversibility`, `blast_radius`, `estimated_cost`,
`state_fingerprint`, `preconditions`, `target_resource`, `effect_type`,
`created_at`/`expires_at` (manifest lifetime).

### `IntelligencePolicy` (`karmasakshi/intelligence/policy.py`)

A frozen, versioned dataclass carrying every threshold the scorer uses:
per-classification base points, monetary-exposure tiers (per currency),
sensitive-target regex patterns, a restricted-effect-type deny-list, a
delegation-depth ceiling, a maximum acceptable historical failure rate,
block/review score thresholds, risk-level score bands, and cooling-off
periods. `IntelligencePolicy.policy_hash()` is a canonical SHA-256 hash of
every field (dict/tuple contents are sorted first, so construction order
never affects the hash) -- this is what a future signed-policy-bundle
phase will wrap and bind into authorization.

This is a **scoring policy only**. It carries no signature yet.

### `AssessmentFacts` (`karmasakshi/intelligence/facts.py`)

Facts the manifest alone cannot supply: delegation depth, historical
recurrence/failure counts, provider idempotency capability, compensation
feasibility, cross-tenant flag, an "unusual parameter change" flag, and a
list of external policy-violation strings. Every field defaults to an
explicit unknown/zero value, never a favorable guess -- an unset
`provider_idempotent` is scored as *more* uncertain than a confirmed
`False`, never as good as a confirmed `True`.

`derive_facts_from_audit(journal, manifest, ...)` populates the
historical-recurrence facts for real by correlating this actor's prior
`manifest.prepared` events (same `effect_type`) against later terminal
events (`effect.committed`/`effect.commit_failed`/etc.) in the audit
journal -- a real query over the hash-chained audit trail, not a stub.
The remaining facts (delegation depth, provider capabilities,
cross-tenant, external policy violations) are not currently derivable
from the audit journal alone and must be supplied by the caller; a
production deployment would source them from the grant/delegation chain,
an adapter capability declaration (Phase 17, not yet implemented), and a
tenant/policy service (Phase 19, not yet implemented).

## Output: `EffectAssessment`

`assessment_id`, `manifest_id`, `manifest_hash`, `policy_id`,
`policy_version`, `policy_hash`, `score` (0-100), `risk_level`
(low/medium/high/critical), `signals` (every named, weighted fact that
contributed), `recommendation` (allow/review/block),
`required_human_approvals`, `required_service_approvals`,
`cooling_off_period_seconds`, `required_witness_quorum`,
`required_verification_strength`, `explanation` (a deterministic
rendering of the signals, never free text), `assessed_at`.

### Determinism

`EffectAssessment.deterministic_payload()`/`.deterministic_hash()` cover
every field **except** `assessment_id` and `assessed_at` (per-call
identity/timestamp, not scoring output). Given the same manifest, the
same policy, and the same facts, two calls -- in the same process, in two
different processes, on two independently constructed
`EffectIntelligenceEngine` instances -- always produce the same
`deterministic_hash()`. This is exercised by
`tests/property/test_intelligence_properties.py` (Hypothesis, 200
examples per property) and pinned by unit tests.

## Scoring signals

See `EffectIntelligenceEngine._score_*` methods in
`karmasakshi/intelligence/engine.py` for the authoritative list; summary:

| Signal | Trigger |
|---|---|
| `declared_risk_classification` / `declared_blast_radius` / `declared_reversibility` | Policy base points per manifest classification |
| `monetary_exposure_tier` | `estimated_cost` vs. policy amount thresholds (0/10/20/35 pts) |
| `unclassified_currency_uses_default_thresholds` | Currency not explicitly configured in the policy |
| `high_risk_without_cost_estimate` | High/critical risk with no `estimated_cost` |
| `no_state_fingerprint_for_non_reversible_effect` | No `state_fingerprint` and not classified reversible |
| `no_preconditions_declared_for_high_risk_effect` | Empty `preconditions` on a high/critical-risk manifest |
| `manifest_lifetime_exceeds_recommended_window` | `expires_at - created_at` over the policy's max recommended TTL |
| `sensitive_target_pattern_matched` | `target_resource` matches a policy-configured regex |
| `sensitive_target_pattern_malformed` | **Forces BLOCK.** A policy regex fails to compile -- fails closed, never silently treated as "no match" |
| `effect_type_restricted_by_policy` | **Forces BLOCK.** `effect_type` is on the policy's restricted list |
| `delegation_depth_exceeds_policy_ceiling` | **Forces BLOCK.** `facts.delegation_depth` over the policy ceiling |
| `delegation_depth_at_ceiling` | Exactly at the ceiling (scored, not blocked) |
| `novel_effect_pattern_no_history` | No prior actor+effect_type instances found |
| `elevated_historical_failure_rate` | Historical failure rate exceeds the policy's acceptable rate |
| `provider_idempotency_unknown` | `facts.provider_idempotent is None` |
| `non_idempotent_provider_high_risk` | Confirmed non-idempotent provider on a high/critical-risk effect |
| `compensation_feasibility_unknown` | `facts.compensation_feasible is None` on a non-reversible effect |
| `compensation_feasibility_contradicts_manifest_reversibility` | **Forces BLOCK.** Manifest declares `compensatable` but facts confirm compensation is infeasible -- an internal contradiction, not a risk level |
| `irreversible_and_not_compensatable` | Irreversible effect with confirmed-infeasible compensation |
| `cross_tenant_effect` | `facts.cross_tenant` (advisory -- multi-tenant enforcement is not implemented) |
| `unusual_parameter_change_detected` | `facts.unusual_parameter_change` |
| `external_policy_violation:<name>` | **Forces BLOCK**, once per entry in `facts.policy_violations` |

A forced-BLOCK signal always wins: no combination of favorable score
elsewhere can turn a forced block into `ALLOW` or `REVIEW` (see
`tests/adversarial/test_intelligence_gaming.py`).

## Integration points

- **Engine**: `KarmaSakshiEngine.assess(manifest, facts=None)`. Like
  `propose()`, this does **not** transition the lifecycle state machine --
  it is an audited side-channel step, callable any number of times between
  `prepare()` and `authorize()`. Every call records an `effect.assessed`
  audit event (hash-chained, same journal as every other engine step).
- **`EngineContext.intelligence`**: an `EffectIntelligenceEngine` bound to
  one policy; defaults to `IntelligencePolicy()` if not overridden, so
  existing `EngineContext(...)` call sites are unaffected.
- **CLI**: `karmasakshi assess <manifest_id>` (see `karmasakshi assess
  --help`), including `--from-audit-history` to derive recurrence facts
  from the workspace's own audit journal, and `--policy-violation` /
  tri-state (`unknown`/`yes`/`no`) flags for the remaining facts.
- **API**: `POST /manifests/{manifest_id}/assess`, `GET
  /manifests/{manifest_id}/assessment`.
- **Action Passport**: `ActionPassport.assessment_*` fields (all
  `None` if `assess()` was never called for that manifest -- fully
  backward compatible with existing passports) and a dedicated "Effect
  Intelligence Assessment" section in the Markdown/HTML renderer.

## Known limitations

- Advisory only -- see "What it is not" above.
- `IntelligencePolicy` is not signed; anyone constructing an
  `EffectIntelligenceEngine` in-process can pick any policy. Binding a
  signed policy bundle into authorization is future work.
- `derive_facts_from_audit`'s recurrence count trusts the audit journal's
  own history uncritically -- it does not distinguish a legitimately
  established pattern from an attacker who has been quietly building up
  "clean" history. `tests/adversarial/test_intelligence_gaming.py`
  confirms that even unlimited favorable history cannot override a
  forced-BLOCK signal, but it does not defend against gaming the
  non-forced score.
- No cross-tenant enforcement exists yet; `cross_tenant` is scored as a
  signal but nothing prevents the underlying cross-tenant access.
- No adapter-capability registry exists yet; `provider_idempotent` and
  `compensation_feasible` must be supplied by the caller rather than read
  from a trusted adapter declaration.
