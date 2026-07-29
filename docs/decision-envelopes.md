# Decision Envelopes and Atomic Plan Authorization

Extreme-v2 Phase 6 adds two mutually exclusive plan-level bindings for an
`ExecutionGrant`, on top of the existing exact `manifest_hash` binding:

1. **Decision Envelope** — a signed, canonical constrained parameter space.
2. **Atomic plan (causal graph)** — membership in one sealed
   `CausalEffectGraph`.

A grant may carry `decision_envelope_hash` *or* `causal_graph_hash`, never
both. Both bindings still require a concrete sealed manifest at
authorization time in this phase; flexible “authorize the envelope first,
pick concrete parameters later, then execute” wiring is intentionally
deferred (see limitations below).

## Parameter constraints

`ParameterConstraint` kinds:

| Kind | Meaning |
|---|---|
| `exact` | Parameter must equal one sealed value |
| `enum` | Parameter must be one of a sorted allow-list |
| `integer_range` | Inclusive `min_int` / `max_int` for an `int` parameter |
| `monetary_range` | Integer minor-units range in a fixed currency |

Evaluation is pure and deterministic. Incomparable shapes fail closed
(`IncomparableConstraintError`), treated as widening.

## Decision Envelope

`DecisionEnvelope` binds:

- exact `effect_type` and `AdapterIdentity`
- `target_resources` allow-list
- named `parameter_constraints`
- optional `max_estimated_cost`
- optional `causal_graph_hash` (pinned *inside* the envelope; the grant still
  records only `decision_envelope_hash`)
- issuer / validity window / nonce / Ed25519 signature

An agent principal cannot be the envelope issuer (invariant #30 applied to
envelopes). `seal_decision_envelope` / `verify_decision_envelope` mirror the
manifest and policy-bundle sealing pattern: recompute hash, verify
signature, enforce the effective window.

`assert_manifest_fits_envelope` checks effect type, adapter, target,
parameter constraints, unknown-key / required-key policy, and cost cap.

`assert_envelope_narrower_or_equal` is the attenuation check used by
adversarial widening tests: a child may only shrink targets, tighten
ranges, keep or add constraints, and may not outlive the parent.

## Deterministic substitution

`substitute_parameters(envelope, choices)` resolves a complete parameter
dict:

- exact constraints are filled automatically
- a caller choice that conflicts with an exact value fails closed
- non-exact constraints require an explicit choice
- unconstrained choice keys are rejected
- result keys are sorted lexicographically

This is library logic in Phase 6 so later execution wiring cannot invent
non-deterministic substitution rules.

## Engine integration

- `KarmaSakshiEngine.authorize_with_envelope(sealed, envelope, ...)` verifies
  the envelope, checks fit, and issues a grant with
  `manifest_hash` + `decision_envelope_hash`.
- `KarmaSakshiEngine.authorize_plan(sealed, graph, ...)` verifies the graph,
  checks node membership, and issues a grant with
  `manifest_hash` + `causal_graph_hash`.
- `commit(..., decision_envelope=..., causal_graph=...)` re-presents and
  re-verifies the bound artifact (same pattern as policy-bundle binding).

## Surfaces

- CLI: `karmasakshi envelope create|verify|substitute`,
  `grant issue --decision-envelope-id` / `--causal-graph-id`,
  `execute --decision-envelope-id` / `--causal-graph-id`
- API: `POST/GET /decision-envelopes`,
  `POST /decision-envelopes/{id}/substitute`,
  `decision_envelope_id` / `causal_graph_id` on `/approve` and `/execute`
- Action Passport: `authorization_decision_envelope_hash`,
  `authorization_causal_graph_hash`

## Security invariants

See `docs/security-model.md` invariants **#39–#42**.

## Known limitations

- Envelope authorization still requires a concrete sealed manifest at
  authorize time. Authorizing an open envelope and substituting later is
  not yet a first-class lifecycle path.
- Envelope-pinned `causal_graph_hash` is evidence inside the envelope hash;
  it does not separately set `ExecutionGrant.causal_graph_hash`.
- Graph-bound grants still authorize one sealed node per grant (with
  membership proof). Multi-node single-grant saga execution is Phase 8.
- Reference API envelope storage is process-local.
