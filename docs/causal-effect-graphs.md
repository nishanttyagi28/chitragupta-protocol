# Causal Effect Graphs

Status: **implemented, advisory only** (extreme-v2 Phase 5). Package: `karmasakshi.causal`.

## What it is

`EffectManifest.parent_manifest_id` (v0.1) is a single unsigned string
field -- nothing verifies that a claimed parent manifest actually
existed, was sealed, or that the causal link is real. Phase 5 adds a
verifiable, cryptographically signed record of causality between two
manifests, independent of that field:

- **`CausalLink`**: a signed edge from one manifest's hash to another's,
  carrying an explicit `relationship` (`triggers`, `compensates`,
  `depends_on`, `supersedes`). Self-signing, structurally identical in
  shape to `ApprovalStatement` -- immutable, tamper-evident, verified
  against a `Keyring` exactly like every other signed artifact in this
  protocol.
- **`CausalEffectGraph`**: an immutable set of `CausalLink`s, with
  `parents_of()`/`children_of()`/`ancestors_of()` traversal and
  `has_cycle()` detection (iterative, so an adversarially deep or dense
  graph cannot exhaust Python's call stack).
- **`verify_causal_graph()`**: independently re-verifies every link's
  signature and checks the whole graph for cycles, returning a
  `CausalGraphVerificationResult` rather than raising -- a single bad
  link is recorded, not fatal to checking the rest (the same
  non-raising-per-item pattern as `evaluate_quorum`).

**Advisory only in this release, exactly like Phase 1's Effect
Intelligence Engine**: nothing in `authorize()`/`commit()` reads or
enforces a causal graph. `KarmaSakshiEngine.record_causal_link()` and
`.verify_causal_graph()` are audited side-channel steps -- like
`assess()`, they never transition the lifecycle state machine and may be
called any number of times, in any order, relative to the rest of a
manifest's lifecycle.

## Why `recorded_by` has no principal-type restriction

Every other signed artifact that influences an authorization outcome
(`ExecutionGrant.issuer`, `ApprovalStatement.approver`,
`PolicyBundle.issuer`) enforces invariant #30: an agent principal can
never be the one making that decision. A `CausalLink` is different in
kind -- it is a *factual claim about what happened* ("this refund
compensates that payment"), not an authorization decision, and it is
never read by `authorize()`/`commit()`. An agent recording that its own
compensating action relates to an earlier effect is exactly the ordinary
case this feature exists for, so `sign_causal_link()` places no
restriction on `recorded_by`. See `causal/signing.py`'s docstring for the
explicit rationale.

## Cycle detection

`CausalEffectGraph.has_cycle()` uses an iterative (not recursive)
depth-first search with white/gray/black node coloring -- entering a node
marks it gray, finishing it marks it black, and encountering an
already-gray node during traversal means a back-edge (a cycle) exists.
Iterative by design so a graph an adversary constructs to be as deep as
the size bound (`MAX_LINKS = 512`) allows can never risk Python's
recursion limit (property-tested in
`tests/property/test_causal_graph_properties.py`, including a maximally
dense 8-node complete digraph and a 511-edge simple chain).

`CausalEffectGraph.ancestors_of()` is a separate, cycle-safe walk (a
visited-set bounds it even over a graph that turns out to be cyclic) used
to populate the Action Passport's `causal_ancestor_hashes` field.

## Binding into the engine

`KarmaSakshiEngine.record_causal_link(*, parent_manifest_hash,
child_manifest_hash, relationship, recorded_by, signing_key, ...)` signs
a `CausalLink` and records a `causal_link.recorded` audit event.
`KarmaSakshiEngine.verify_causal_graph(links)` assembles a
`CausalEffectGraph`, verifies it, and records a `causal_graph.verified`
audit event either way (`satisfied`/`invalid` decision). Neither method
appears anywhere in `authorize()`, `authorize_with_quorum()`, or
`commit()` -- there is no code path where recording or verifying a
causal link changes whether an effect is authorized or executed.

## Action Passport

`ActionPassport` gained three fields:

- `causal_ancestor_hashes: tuple[str, ...]` -- every manifest hash this
  one causally descends from (transitively), computed from a
  caller-supplied `CausalEffectGraph`. Empty if no graph was supplied.
- `causal_graph_verified: bool | None` -- whether every link in the
  supplied graph verified and no cycle was found. `None` if no graph was
  supplied.
- `causal_graph_reason: str | None` -- a human-readable explanation
  (e.g. `"a cycle was detected"`, `"1 link(s) failed signature
  verification"`).

Unlike `role_participation` (Phase 4), which `build_passport()`
reconstructs automatically from the audit trail, the causal graph is
**not** auto-derived -- a caller must explicitly pass `causal_graph=...`.
This is a deliberate difference: a role assignment is scoped to one
`grant.issued` audit event for the manifest itself, but a causal graph
can span arbitrarily many unrelated manifests, and there is no single
natural audit-trail location to reconstruct "the whole graph relevant to
this manifest" from. The CLI's `passport` command loads every causal
link ever recorded in the workspace and passes it automatically; the API
control plane does the same with every link recorded in that process's
state.

## CLI

```text
karmasakshi causal record <parent_manifest_id> <child_manifest_id>
    --recorded-by-id ID [--recorded-by-type human|service|agent]
    --key-id ID [--relationship triggers|compensates|depends_on|supersedes]
karmasakshi causal verify   # verifies every link ever recorded in this workspace
```

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/causal-links` | Sign and record a causal link between two manifests |
| GET | `/causal-links` | List every causal link recorded in this control plane |
| POST | `/causal-links/verify` | Verify every recorded link's signature and check for cycles |

## Known limitations

- **Advisory only.** Nothing enforces that a claimed causal relationship
  is real beyond the signature proving *who* claimed it -- an agent (or
  anyone else) can sign a link asserting a causal relationship that
  doesn't actually reflect reality; the protocol only guarantees the
  claim is tamper-evident and attributable, not that it's true.
- **No automatic linkage to `EffectManifest.parent_manifest_id`.** The
  v0.1 field and Phase 5's signed links are independent; nothing
  cross-checks one against the other.
- **No revocation-propagation semantics.** Unlike delegation (where a
  parent grant's revocation propagates one hop), revoking or disputing a
  causal link has no defined effect on anything -- there is no
  "causal link revoked" concept in this release.
- **The causal graph is not auto-derived for passports** -- see "Action
  Passport" above.
