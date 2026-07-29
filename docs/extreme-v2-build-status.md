# Build Status — KarmaSakshi Protocol "extreme-v2"

_Last updated: 2026-07-29_

This ledger tracks work beyond the v0.1.0 baseline documented in
[`BUILD_STATUS.md`](../BUILD_STATUS.md), toward the 25-phase program
described in the extreme-v2 mission. It is deliberately honest about
scope: most of the 25 phases are **not implemented**. Read this file
before believing any marketing claim about this branch.

Branch: `feat/karmasakshi-extreme-v2` (this session's harness pushed it as
`claude/karmasakshi-extreme-v2-lhmdqc`, tracking the same intent).

## Baseline audit (this session, before any phase work)

Recorded exactly as observed, not assumed:

| Check | Result |
|---|---|
| `pytest` | 295 passed, 6 skipped, **1 failed** (`test_canonical_bytes_have_no_insignificant_whitespace` -- a genuine false positive in the property test itself, not the implementation: it asserted no literal `": "` substring anywhere in canonical JSON bytes, but a string *value* containing `": "` legitimately encodes to a quoted JSON string containing that substring) |
| `ruff check` / `ruff format --check` | Clean |
| `mypy src` | Clean (0 errors, 80 files) |
| `bandit -r src/karmasakshi` | Clean |
| `python -m build` | PASS |
| `python -m twine check dist/*` | **FAIL** -- twine 5.1.1 (the pinned dev version) cannot parse the `Metadata-Version: 2.4` hatchling now emits (PEP 639 `License-Expression`); a tooling-version issue, not a real packaging defect |
| `pip-audit` | 1 known vulnerability: `pytest 8.4.2`, `PYSEC-2026-1845`, fix in `9.0.3` (dev-only dependency) |
| Architecture | See `BUILD_STATUS.md` phases 1-16: domain/canonical/crypto/grants/state-machine/engine/stores/delegation/audit/passports/adapters/langgraph/cli/api/agenteval, 30 documented security invariants (`docs/security-model.md`) |

**Baseline fix commit** (`900c87b`, before any extreme-v2 feature work):
fixed the property-test false positive (constrained the Hypothesis string
strategy to exclude the structural separators it's actually testing for)
and bumped the dev-group `twine` pin to `>=6.0,<8`. After this commit:
**296 passed, 6 skipped**, `twine check` clean. The `pytest` CVE was left
unaddressed (a major-version bump of the test framework is out of scope
for a baseline hygiene fix) and is recorded here, not silently dropped.

## Phase status

| Phase | Status | Notes |
|---|---|---|
| 1. Effect Intelligence | **Implemented** (advisory only) | See below |
| 2. Signed policy bundles | **Implemented** | See below |
| 3. Multi-party (M-of-N) authorization | **Implemented** | See below |
| 4. Separation of duties (explicit roles) | **Implemented** | See below |
| 5. Causal effect graphs | **Implemented** (advisory only) | See below |
| 6. Atomic plan authorization / decision envelopes | Not started | |
| 7. Compensation manifests | Not started | Compensation remains the v0.1 `CompensationResult` model (best-effort, honestly reported) |
| 8. Saga orchestration | Not started | |
| 9. Independent witness quorum | Not started | |
| 10. Evidence quality and provenance | Not started | |
| 11. Deep delegation revocation | Not started | v0.1's one-hop revocation propagation (documented limitation) is unchanged |
| 12. Authority budgets | Not started | |
| 13. Durable lifecycle storage | Not started | Lifecycle state remains process-local + audit-journal-reconstructed, as in v0.1 |
| 14. Distributed audit journal | Not started | SQLite/Redis backends are v0.1; no new distributed-consensus work |
| 15. Transactional outbox | Not started | |
| 16. Production signer interface | Not started | Ed25519 dev keys only, as in v0.1 |
| 17. Trusted adapter registry | Not started | |
| 18. Adapter conformance kit | Not started | |
| 19. Multi-tenant control plane | Not started | `AssessmentFacts.cross_tenant` exists as a scoring input (Phase 1) but nothing enforces tenant isolation |
| 20. Resource/DoS protection | Not started | |
| 21. Adversarial/fuzz testing | Partial | Phase 1's own scoring engine has adversarial + property coverage; no new coverage added for pre-existing v0.1 components beyond the baseline fix |
| 22. State-machine model checking | Not started | v0.1's `tests/property/test_state_machine_properties.py` (BFS reachability) is unchanged |
| 23. Action Passport V2 | Not started | Phase 1 added optional `assessment_*` fields to the existing (v1) passport rather than a new versioned schema |
| 24. Portable evidence / observability | Not started | |
| 25. AgentEval failure-memory loop | Not started | v0.1's AgentEval bridge (versioned, neutral export) is unchanged |

## Phase 1: Effect Intelligence Engine

**Status: implemented, advisory only.**

### Files changed

- Added: `src/karmasakshi/intelligence/{__init__,policy,facts,model,engine}.py`
- Added: `src/karmasakshi/cli/assess_cmd.py`
- Added: `docs/effect-intelligence.md`
- Added: `tests/unit/test_intelligence.py`,
  `tests/property/test_intelligence_properties.py`,
  `tests/adversarial/test_intelligence_gaming.py`
- Modified: `src/karmasakshi/engine/context.py` (`EngineContext.intelligence`),
  `src/karmasakshi/engine/core.py` (`KarmaSakshiEngine.assess()`),
  `src/karmasakshi/cli/app.py`, `src/karmasakshi/cli/workspace.py`,
  `src/karmasakshi/cli/passport_cmd.py`,
  `src/karmasakshi/api/{routes,schemas,state}.py`,
  `src/karmasakshi/passports/{model,generator,render}.py`,
  `tests/conftest.py` (extended `make_manifest`/`manifest_factory` with
  optional `risk`/`reversibility`/`blast_radius`/`estimated_cost`/
  `preconditions` params, all defaulting to the prior hardcoded values --
  backward compatible with every existing call site),
  `tests/unit/test_engine.py`, `tests/integration/{test_api,test_cli}.py`
- Docs updated: `docs/threat-model.md` (new "Effect Intelligence Engine"
  trust-boundary section), `docs/limitations.md`, `docs/state-machine.md`
  ("ASSESS is not a state"), `docs/api.md`, `docs/cli.md`, `README.md`,
  `CHANGELOG.md`

### Tests added

- 48 unit tests (`test_intelligence.py`): policy/facts construction and
  validation, every individual scoring signal, monetary-tier boundaries,
  determinism across engine instances, `derive_facts_from_audit` against
  a real `AuditJournal`.
- 6 Hypothesis property tests (`test_intelligence_properties.py`, 200
  examples each): score always in [0, 100]; `deterministic_hash()`
  identical across repeated calls and across independently constructed
  engine instances; recommendation consistent with score thresholds;
  required approvals never exceed the policy ceiling; higher monetary
  exposure never scores lower.
- 10 adversarial tests (`test_intelligence_gaming.py`): forced-BLOCK
  signals (restricted effect type, delegation-depth ceiling breach,
  external policy violation) cannot be offset by any amount of favorable
  history; a manifest that self-contradicts (`compensatable` +
  confirmed-infeasible) can never resolve to `ALLOW`; a malformed policy
  regex fails closed (forces BLOCK, never silently "no match"); score
  cannot go negative; different policies produce different `policy_hash`
  values.
- Engine integration tests (`test_engine.py`): `assess()` records exactly
  one `effect.assessed` audit event per call with the correct
  decision/metadata, does not transition the lifecycle state machine, and
  respects a caller-supplied `EngineContext.intelligence` policy.
- API integration tests (`test_api.py`): `POST .../assess`,
  `GET .../assessment` (including 404s), and the passport now surfacing
  assessment fields.
- CLI integration tests (`test_cli.py`): `karmasakshi assess`, tri-state
  flag validation, `--policy-violation`, `--from-audit-history`, and the
  passport's new Markdown section.

### Security invariants added

None of the existing 30 invariants (`docs/security-model.md`) were
changed. No new invariant was added to that table, deliberately: `assess()`
is advisory and does not gate `authorize()`/`commit()`, so it would be
dishonest to list it alongside invariants that are structurally enforced.
The one property this phase *does* guarantee and test for is
determinism: **the same manifest + policy + facts always produce the
same `EffectAssessment.deterministic_hash()`**, which is the basis a
future signed-policy-bundle phase would build enforcement on.

### Known limitations

See `docs/effect-intelligence.md`'s "Known limitations" section in full;
summary: advisory only (not wired into authorize()/commit()); policy is
unsigned; `derive_facts_from_audit`'s recurrence count trusts audit
history uncritically (an attacker who has built up "clean" history is not
detected, though forced-BLOCK signals still cannot be overridden by it);
no cross-tenant enforcement exists yet (`cross_tenant` is scored, not
enforced); no adapter-capability registry exists yet (idempotency/
compensation-feasibility facts must be supplied by the caller).

### Verification commands

Run from a fresh `uv venv .venv --python 3.12 && uv pip install -e
".[all]" --python .venv/bin/python && uv pip install --group dev --python
.venv/bin/python`:

```bash
ruff check .
ruff format --check .
mypy src
bandit -r src/karmasakshi
python -m pytest -q
python -m pytest -q tests/unit/test_intelligence.py tests/property/test_intelligence_properties.py tests/adversarial/test_intelligence_gaming.py
python -m build && python -m twine check dist/*
pip-audit
```

Results at the time of this commit: `ruff check`/`ruff format --check`/
`mypy src`/`bandit` all clean; `pytest -q` → **374 passed, 6 skipped**
(Redis-only tests, no local Redis in this environment -- documented, not
fabricated); `build`/`twine check` clean; `pip-audit` → 1 known
vulnerability (`pytest` 8.4.2, dev-only, noted above, unresolved).

### Commit SHAs / PR

- `900c87b` — baseline test/tooling fixes (pre-Phase-1)
- `739ecc3` — Phase 1: Effect Intelligence Engine implementation, tests, docs
- `d22db89` — Phase 1: build ledger
- PR [#15](https://github.com/nishanttyagi28/karmasakshi-protocol/pull/15) — merged (`3ceebcb`), all 14 CI checks green

## Phase 2: Signed Policy Bundles

**Status: implemented.**

### Files changed

- Added: `src/karmasakshi/policy/{__init__,bundle,sealing}.py`
- Added: `src/karmasakshi/cli/policy_cmd.py`
- Added: `docs/policy-bundles.md`
- Added: `tests/unit/test_policy_bundles.py`,
  `tests/property/test_policy_bundle_properties.py`,
  `tests/adversarial/test_policy_bundle_gaming.py`
- Modified: `src/karmasakshi/errors/__init__.py` (6 new `PolicyBundleError`
  subclasses), `src/karmasakshi/intelligence/policy.py`
  (`build_policy_bundle`/`policy_from_bundle_payload`,
  `POLICY_TYPE_INTELLIGENCE`), `src/karmasakshi/grants/model.py`
  (`ExecutionGrant.policy_bundle_hash`, `is_policy_bundle_bound()`),
  `src/karmasakshi/grants/issuer.py` (`issue_grant(policy_bundle_hash=...)`),
  `src/karmasakshi/engine/core.py` (`authorize(policy_bundle=...)`,
  `commit(policy_bundle=...)`), `src/karmasakshi/cli/app.py`,
  `src/karmasakshi/cli/{grant_cmd,execute_cmd,workspace}.py`
  (`--policy-bundle-id`), `src/karmasakshi/api/{schemas,state,routes}.py`
  (`/policy/bundles*`, `policy_bundle_id` on `/approve`/`/execute`),
  `src/karmasakshi/passports/{model,generator,render}.py`
  (`authorization_policy_bundle_hash`)
- Docs updated: `docs/security-model.md` (invariants #31, #32),
  `docs/threat-model.md` implicitly covered by the "New trusted
  component" section already added for Phase 1 (policy bundles are the
  same trust class); `docs/execution-grants.md`, `docs/protocol-spec.md`,
  `docs/cli.md`, `docs/api.md`, `README.md`, `CHANGELOG.md`

### Tests added

- 16 unit tests (`test_policy_bundles.py`): construction/validation
  (effective window ordering, oversized payload), hash determinism
  regardless of dict/tuple construction order, seal/verify round trip,
  type-mismatch/not-yet-effective/expired/tampered/unknown-key/forged-
  signature rejection, `IntelligencePolicy` <-> payload round trip
  (including malformed-payload rejection).
- 3 Hypothesis property tests (`test_policy_bundle_properties.py`, 100-200
  examples each): arbitrary `IntelligencePolicy` values round-trip
  through a bundle payload with an identical `policy_hash()`; bundle hash
  is stable across repeated builds of the same policy; effective-window
  membership is consistent (`is_effective_at` at the boundaries).
- 7 adversarial tests (`test_policy_bundle_gaming.py`): agent-issuer
  rejection, expired-bundle replay, seal/bundle "frankenstein" grafting
  (stolen signature over swapped content), unknown-signer rejection,
  cross-bundle signature reuse, forged-signature-over-correct-hash.
- Engine integration tests (`test_engine.py`, 6 new): `authorize()` binds
  the bundle hash into the grant; `commit()` succeeds with the matching
  bundle; **the core security property** -- `commit()` rejects a missing
  bundle, a swapped (different but validly-signed) bundle, and a
  tampered bundle, each with a specific error; a grant issued without a
  policy bundle is unaffected by an extraneous one being passed
  (backward-compatibility regression test).
- API integration tests (`test_api.py`, 6 new): bundle create/get/verify,
  agent-issuer 422, not-found 404s, `/approve`+`/execute` binding and
  rejecting a swapped bundle (`409`), passport surfacing the bound hash.
- CLI integration tests (`test_cli.py`, 4 new): `policy create/sign/verify`
  round trip, verify-before-sign failure, and a full `grant issue
  --policy-bundle-id` / `execute --policy-bundle-id` cycle against the
  SQLite adapter proving the missing-bundle case fails and the matching
  case succeeds.
- Full existing suite remains green throughout (414 passed, 6 skipped --
  no regressions from either phase).

### Security invariants added

- **#31**: A grant bound to a policy bundle cannot commit against a
  missing, different, tampered, expired, or untrusted-signer policy
  bundle (`engine.commit()`'s `policy_bundle_hash` check, only active
  when the grant declares one -- fully backward compatible).
- **#32**: An agent principal cannot be the issuer of a signed policy
  bundle (`build_policy_bundle()`, mirroring invariant #30).

### Known limitations

See `docs/policy-bundles.md`'s "Known limitations" section in full;
summary: not yet an enforcement gate on `EffectAssessment.recommendation`
(Phase 2 gives a cryptographically pinned *reference*, not automatic
blocking -- that is explicitly deferred to a later phase, per the prior
ledger's own guidance, to avoid wiring enforcement in before the binding
existed); `tenant_id` is metadata only, not enforced; only
`policy_type == "intelligence.v1"` is currently interpretable.

### Verification commands

Same procedure as Phase 1 (see above). Results at the time of this
commit: `ruff check`/`ruff format --check`/`mypy src`/`bandit` all clean;
`pytest -q` → **414 passed, 6 skipped**; `pytest --cov=karmasakshi
--cov-fail-under=90` → 92%; `build`/`twine check` clean; `pip-audit` → the
same 1 known dev-only vulnerability as Phase 1 (unchanged, unresolved).

### Commit SHAs / PR

- `d9a941b` — Phase 2: Signed Policy Bundles implementation, tests, docs
- PR [#16](https://github.com/nishanttyagi28/karmasakshi-protocol/pull/16) — merged (`99db98e`), all 14 CI checks green

## Phase 3: Multi-party (M-of-N) Authorization

**Status: implemented.**

### Files changed

- Added: `src/karmasakshi/approval/{__init__,model,policy,quorum,signing}.py`
- Added: `src/karmasakshi/cli/approve_cmd.py`
- Added: `docs/multi-party-authorization.md`
- Added: `tests/unit/test_approval.py`,
  `tests/property/test_approval_quorum_properties.py`,
  `tests/adversarial/test_approval_gaming.py`
- Modified: `src/karmasakshi/errors/__init__.py` (5 new `ApprovalError`
  subclasses), `src/karmasakshi/grants/model.py`
  (`ExecutionGrant.approval_set_hash`, `is_quorum_bound()`),
  `src/karmasakshi/grants/issuer.py` (`issue_grant(approval_set_hash=...)`),
  `src/karmasakshi/engine/core.py` (`authorize_with_quorum()`),
  `src/karmasakshi/cli/{app,grant_cmd,policy_cmd,workspace}.py`
  (`approve`, `approvals inspect`, `grant issue-with-quorum`, `policy
  create-approval`), `src/karmasakshi/api/{schemas,state,routes}.py`
  (`/policy/approval-bundles`, `/manifests/{id}/approvals[/evaluate]`,
  `/manifests/{id}/approve-with-quorum`),
  `src/karmasakshi/passports/{model,generator,render}.py`
  (`authorization_approval_set_hash`)
- Docs updated: `docs/security-model.md` (invariants #33-#36),
  `docs/threat-model.md` (new trusted-component section covering both
  Phase 2 and Phase 3), `docs/execution-grants.md`, `docs/limitations.md`,
  `docs/cli.md`, `docs/api.md`, `README.md`, `CHANGELOG.md`

### Tests added

- 29 unit tests (`test_approval.py`): `ApprovalPolicy` validation,
  policy<->bundle payload round trip, agent-issuer rejection for approval
  policy bundles, statement signing/verification (expired, unknown
  signer, forged signature), and `evaluate_quorum` coverage (N-of-M,
  role requirements, proposer/subject exclusion, agent-approver
  rejection via direct model construction, duplicate-approver dedup,
  dissent veto on/off, wrong manifest/bundle hash, cooling-off, batch
  size limit, order-independent `approval_set_hash`).
- 2 Hypothesis property tests (`test_approval_quorum_properties.py`, 100-150
  examples each): the quorum verdict (`satisfied`, `approving_count`,
  `approving_principal_ids`, `dissenting_principal_ids`, `missing_roles`,
  `approval_set_hash`) is identical regardless of statement order across
  randomized statement sets, required-approval counts, and veto settings;
  approving count never exceeds the number of distinct approvers.
- 6 adversarial tests (`test_approval_gaming.py`): replay against a
  different manifest, identity collision (two keys claiming the same
  principal_id counted once), a later dissent overriding an earlier
  approval from the same approver (and the reverse presentation order
  producing the same result), a stale approval replay failing to
  override a later dissent, proposer+subject exclusion leaving no
  exploitable gap, and a tampered role claim failing signature
  verification.
- Engine integration tests (`test_engine.py`, 4 new):
  `authorize_with_quorum()` succeeds with sufficient approvals and binds
  `approval_set_hash`; raises `QuorumNotMetError` when quorum isn't met;
  a dissent vetoes even when the raw count would otherwise satisfy
  quorum; a quorum-issued grant commits via the ordinary `commit()` path
  with no approval-set re-presentation required.
- API integration tests (`test_api.py`, 3 new): full create-approval-bundle
  → submit approvals → evaluate → approve-with-quorum → execute cycle;
  `403` when quorum isn't met; `422` for an agent-typed approval-bundle
  issuer.
- CLI integration tests (`test_cli.py`, 2 new): full
  `policy create-approval` → `policy sign` → `approve` (x2) →
  `approvals inspect` → `grant issue-with-quorum` → `execute` cycle
  against the sqlite adapter (including the pre-quorum failure case);
  a dissenting statement blocking `grant issue-with-quorum` end to end.
- Full existing suite remains green throughout (460 passed, 6 skipped --
  no regressions across all three phases).

### Security invariants added

- **#33**: A grant issued via `authorize_with_quorum()` is structurally
  impossible without a satisfied approval quorum.
- **#34**: An agent principal can never satisfy approval quorum, and can
  never sign an approval statement.
- **#35**: The proposer of a manifest and the subject/executor of a grant
  can never satisfy that grant's approval quorum (when required, the
  default).
- **#36**: Quorum evaluation is deterministic and order-independent,
  including when one approver submitted conflicting statements (latest
  `signed_at` wins, not submission order).

### Known limitations

See `docs/multi-party-authorization.md`'s "Known limitations" section in
full; summary: approval roles are self-asserted (no RBAC/identity
directory); the reference API signs every approval statement with one
shared service key rather than a distinct key per approver (the CLI does
not have this limitation -- each workspace key is genuinely separate);
`commit()` does not re-verify the approval set (by design, documented
rationale, not an oversight); `EffectAssessment.required_human_approvals`
(Phase 1) is not yet automatically wired into `ApprovalPolicy.required_approvals`.

### Verification commands

Same procedure as Phases 1-2 (see above). Results at the time of this
commit: `ruff check`/`ruff format --check`/`mypy src`/`bandit` all clean;
`pytest -q` → **460 passed, 6 skipped**; `build`/`twine check` clean;
`pip-audit` → the same 1 known dev-only vulnerability as Phases 1-2
(unchanged, unresolved).

### Commit SHAs / PR

- `459bc5c` — Phase 3: Multi-Party (M-of-N) Authorization implementation, tests, docs
- PR [#17](https://github.com/nishanttyagi28/karmasakshi-protocol/pull/17) — merged (`ffdf015`), all 14 CI checks green

## Phase 4: Separation of Duties

**Status: implemented.**

### Files changed

- Added: `src/karmasakshi/duty/{__init__,roles,policy,enforcement}.py`
- Added: `docs/separation-of-duties.md`
- Added: `tests/unit/test_separation_of_duty.py`,
  `tests/property/test_separation_of_duty_properties.py`,
  `tests/adversarial/test_separation_of_duty_gaming.py`
- Modified: `src/karmasakshi/errors/__init__.py` (`SeparationOfDutyError`,
  `SeparationOfDutyViolationError`, `RoleAssignmentError`),
  `src/karmasakshi/engine/core.py` (`authorize()`/`authorize_with_quorum()`
  gain `separation_policy_bundle`/`role_assignment`;
  `_enforce_separation_of_duty()` helper shared by both;
  `_role_participation_metadata()` flattens role facts into
  `grant.issued` audit metadata), `src/karmasakshi/passports/{model,generator}.py`
  (`role_participation` field, reconstructed from the audit trail
  automatically), `src/karmasakshi/passports/render.py` (new passport
  section), `src/karmasakshi/cli/{policy_cmd,grant_cmd}.py`
  (`policy create-separation`, `--separation-policy-bundle-id`/`--role`
  on `grant issue`/`grant issue-with-quorum`),
  `src/karmasakshi/api/{schemas,routes}.py` (`/policy/separation-bundles`,
  the same two optional fields on `/approve` and `/approve-with-quorum`)
- Docs updated: `docs/security-model.md` (invariants #37-#38, title
  corrected to "38 Invariants"), `docs/threat-model.md` (extended the
  Phase 2/3 trusted-component section), `docs/execution-grants.md`,
  `docs/action-passports.md`, `docs/limitations.md`, `docs/cli.md`,
  `docs/api.md`, `README.md` (invariant count corrected in two more
  places), `CHANGELOG.md`

### Tests added

- 26 unit tests (`test_separation_of_duty.py`): `RoleAssignment`
  structural validation (malformed hash, unknown role, empty/duplicate
  principal, oversized batch), `principals_for`/`merge`/
  `as_role_participation`, `base_role_assignment`, `SeparationOfDutyPolicy`
  validation (self-paired role, duplicate order-independent pair,
  oversized matrix), policy-hash order-independence, bundle payload
  round trip, agent-issuer rejection, and `check_separation_of_duty`
  coverage (no violation, single violation, one-violation-per-offending-pair,
  multi-approver overlap, empty matrix never violates).
- 4 Hypothesis property tests (`test_separation_of_duty_properties.py`):
  the check result is independent of role-assignment entry order and of
  forbidden-pair order; an empty matrix is always satisfied; adding more
  forbidden pairs is monotonic (never turns a violation into satisfied).
- 5 adversarial tests (`test_separation_of_duty_gaming.py`): a
  role_assignment bound to the wrong manifest hash is rejected before
  any grant work happens; a tampered separation policy bundle is
  rejected; a custom (non-default) forbidden pair is actually enforced,
  not silently ignored; a blocked `authorize()` call leaves the
  lifecycle state and grant store completely untouched; a single
  conflicted approver among several clean ones under quorum still
  blocks (not diluted by majority).
- Engine integration tests (`test_engine.py`, 9 new): `authorize()`
  blocked when issuer==proposer under the default matrix; succeeds when
  roles are cleanly separated; blocked by an explicit additional-role
  conflict (sealer==approver); fully additive when no bundle is given
  (a real conflict passes through untouched); `authorize_with_quorum()`
  blocked when one counted approver overlaps the proposer (via an
  explicit extra role, isolating Phase 4's check from Phase 3's own
  proposer-exclusion); succeeds with disjoint roles; wrong `policy_type`
  bundle rejected (`PolicyBundleTypeMismatchError`); `grant.issued`
  audit metadata carries `role:<role>` entries even with no bundle bound.
- API integration tests (`test_api.py`, 4 new): create/verify a
  separation bundle; agent-issuer rejection; `/approve` with a bound
  bundle succeeds and the passport's `role_participation` reflects it;
  `/approve` with a genuine proposer==approver conflict returns `403`.
- CLI integration tests (`test_cli.py`, 2 new): full `policy
  create-separation` -> `policy sign` -> `grant issue` -> `execute` ->
  `passport --format json` cycle against the sqlite adapter, asserting
  `role_participation`; a role conflict blocking `grant issue` with a
  non-zero exit code.
- Full existing suite remains green throughout (509 passed, 6 skipped --
  no regressions across all four phases).

### Security invariants added

- **#37**: A grant issued via `authorize()`/`authorize_with_quorum()`
  with a bound separation-of-duty policy cannot exist if any principal
  holds both roles of a forbidden pair.
- **#38**: Separation-of-duty evaluation is deterministic and
  order-independent.

### Design decisions

- **Auto-derived base roles, caller-supplied extras.** The engine
  derives `proposer`/`executor`/`approver` itself (from parameters it
  already has); anything beyond that (`sealer`, `witness`, etc.) is an
  explicit, caller-supplied `RoleAssignment`, merged in and validated
  against the same manifest hash. This mirrors the trust level already
  extended to `issuer`/`subject`/`proposer` elsewhere -- no new trust
  model introduced.
- **No persisted grant field, no commit()-time re-verification.** Unlike
  `policy_bundle_hash`/`approval_set_hash`, separation of duty has
  nothing bound onto `ExecutionGrant` -- it's a one-time
  authorization-time gate, not a swappable, re-editable artifact.
  Documented explicitly (docs/separation-of-duties.md, docs/execution-grants.md)
  so this reads as a deliberate choice, not a gap.
- **Passport role_participation is read from the audit trail
  automatically**, not threaded through every call site -- `grant.issued`
  audit metadata always carries the combined role assignment (`role:<role>`
  keys), so `build_passport()` reconstructs it with zero extra plumbing
  required from CLI/API callers, while still accepting an explicit
  `role_assignment` override for callers that already have one in hand.

### Verification commands

Same procedure as Phases 1-3. Results at the time of this commit:
`ruff check`/`ruff format --check`/`mypy src`/`bandit` all clean;
`pytest -q` → **509 passed, 6 skipped**; `pytest --cov=karmasakshi` →
**90.98%** total; `build`/`twine check` clean; `pip-audit` → the same 1
known dev-only vulnerability as Phases 1-3 (unchanged, unresolved).

### Commit SHAs / PR

- `ee28813` — Phase 4: Separation of Duties implementation, tests, docs
- PR [#18](https://github.com/nishanttyagi28/karmasakshi-protocol/pull/18) — merged (`5eb9ab4`), all 14 CI checks green

## Phase 5: Causal Effect Graphs

**Status: implemented, advisory only.**

### Files changed

- Added: `src/karmasakshi/causal/{__init__,model,signing,graph}.py`
- Added: `src/karmasakshi/cli/causal_cmd.py`
- Added: `docs/causal-effect-graphs.md`
- Added: `tests/unit/test_causal_graph.py`,
  `tests/property/test_causal_graph_properties.py`,
  `tests/adversarial/test_causal_graph_gaming.py`
- Modified: `src/karmasakshi/errors/__init__.py` (`CausalGraphError`,
  `CausalGraphTooLargeError`), `src/karmasakshi/engine/core.py`
  (`record_causal_link()`, `verify_causal_graph()`, both audited
  side-channel steps like `assess()`), `src/karmasakshi/passports/{model,generator,render}.py`
  (`causal_ancestor_hashes`/`causal_graph_verified`/`causal_graph_reason`,
  populated only when a caller passes `causal_graph=...` explicitly),
  `src/karmasakshi/cli/workspace.py` (`causal_dir`,
  `save_causal_link`/`load_causal_link`/`load_all_causal_links`),
  `src/karmasakshi/cli/{app,passport_cmd}.py` (`causal` sub-app
  registered; `passport` auto-includes the workspace's whole causal
  graph), `src/karmasakshi/api/{schemas,state,routes}.py`
  (`/causal-links`, `/causal-links/verify`; `/passports/{id}`
  auto-includes the control plane's whole causal graph)
- Docs updated: `docs/security-model.md` (no new invariant -- see
  "Security invariants added" below), `docs/threat-model.md` (new
  "trusted component" section, mirroring Phase 1's), `docs/action-passports.md`,
  `docs/limitations.md`, `docs/cli.md`, `docs/api.md`, `README.md`,
  `CHANGELOG.md`

### Tests added

- 14 unit tests (`test_causal_graph.py`): `CausalLink` self-reference and
  malformed-hash rejection, signing round trip, unknown-key and
  tampered-content signature failures, agent `recorded_by` explicitly
  allowed, oversized-graph rejection, `parents_of`/`children_of`/
  `ancestors_of` correctness (including a transitive chain and a
  cycle-safe walk over a cyclic graph), `has_cycle` on acyclic/cyclic
  graphs, and `verify_causal_graph` coverage (all valid, invalid
  signature reported without raising, cycle reported).
- 4 Hypothesis property tests (`test_causal_graph_properties.py`):
  `has_cycle`/`ancestors_of` are independent of link submission order
  across randomized edge sets; a 511-edge simple chain (just under
  `MAX_LINKS`) does not raise a recursion error; a maximally dense 8-node
  complete digraph is correctly detected as cyclic.
- 5 adversarial tests (`test_causal_graph_gaming.py`): a forged
  link (content changed, old signature replayed) is caught; a key-swap
  attack (attacker's own key, never registered in the keyring) is
  rejected; a 20-hop chain that closes into a cycle only at the very end
  is still detected; the `MAX_LINKS` bound cannot be bypassed by
  constructing a `CausalEffectGraph` directly; verification checks every
  link independently rather than stopping at the first invalid one.
- Engine integration tests (`test_engine.py`, 5 new):
  `record_causal_link()` returns a correctly signed link and records a
  `causal_link.recorded` audit event; it does not transition lifecycle
  state; `verify_causal_graph()` reports satisfied for a clean chain and
  reports (without raising) a cycle for cyclic input; ordinary
  `authorize()`/`commit()` proceed completely unaffected when no causal
  link is ever recorded (proving the advisory-only claim in code, not
  just in docs).
- API integration tests (`test_api.py`, 3 new): full record -> list ->
  verify -> passport cycle, confirming `causal_graph_verified` appears
  correctly; unknown parent/child manifest 404s; a 2-cycle is correctly
  reported by `/causal-links/verify`.
- CLI integration tests (`test_cli.py`, 2 new): full `causal record` ->
  `causal verify` -> `passport --format json` cycle against the sqlite
  adapter, asserting `causal_graph_verified`/`causal_ancestor_hashes`; a
  2-cycle correctly reported by `causal verify`.
- Full existing suite remains green throughout (542 passed, 6 skipped --
  no regressions across all five phases).

### Security invariants added

**None.** Causal effect graphs are advisory only in this release, the
same posture Phase 1's Effect Intelligence Engine took -- nothing in
`authorize()`/`authorize_with_quorum()`/`commit()` reads or enforces a
causal graph, so there is no new structural guarantee to number and
table in `docs/security-model.md`. This is a deliberate, honestly
documented scope boundary, not an oversight -- see "Known limitations"
in docs/causal-effect-graphs.md.

### Design decisions

- **Iterative, not recursive, cycle detection.** `CausalEffectGraph.has_cycle()`
  uses an explicit stack rather than function recursion so a graph built
  up to the `MAX_LINKS = 512` bound can never risk Python's recursion
  limit -- property-tested against both a 511-edge simple chain and a
  maximally dense 8-node complete digraph.
- **No principal-type restriction on `recorded_by`.** Every other signed
  artifact that influences authorization (`ExecutionGrant.issuer`,
  `ApprovalStatement.approver`, `PolicyBundle.issuer`) enforces
  invariant #30. A `CausalLink` is a factual claim, never read by
  `authorize()`/`commit()`, so an agent recording its own causal claims
  (e.g. "this compensating refund relates to that payment") is the
  ordinary case, not a security gap.
- **The causal graph is not auto-derived for passports**, unlike
  Phase 4's `role_participation`. A role assignment is scoped to one
  `grant.issued` audit event for the manifest itself; a causal graph can
  span arbitrarily many unrelated manifests with no single natural
  audit-trail location to reconstruct "the relevant graph" from. The CLI
  and API both work around this by passing every link they know about
  (the whole workspace/process's graph) rather than trying to scope it
  automatically -- documented as a known simplification, not scaled for
  a deployment with many unrelated manifest graphs in one workspace.

### Verification commands

Same procedure as Phases 1-4. Results at the time of this commit:
`ruff check`/`ruff format --check`/`mypy src`/`bandit` all clean;
`pytest -q` → **542 passed, 6 skipped**; `pytest --cov=karmasakshi` →
**91.30%** total; `build`/`twine check` clean; `pip-audit` → the same 1
known dev-only vulnerability as Phases 1-4 (unchanged, unresolved).

### Commit SHAs / PR

Recorded after this slice's PR is opened and merged, matching the
pattern established for Phases 1-4.

## Exact next executable step

**Phase 6: Atomic Plan Authorization / Decision Envelopes.** Concretely:

1. Today, each `EffectManifest` is authorized independently -- there is
   no way to bind "these N effects must all be authorized together, as
   one atomic decision" (e.g. "debit account A and credit account B, or
   neither"). Phase 6 should introduce a signed `PlanEnvelope` (or
   similar) wrapping an ordered or unordered set of manifest hashes with
   an explicit atomicity requirement.
2. Decide the enforcement boundary precisely and document it: does
   `authorize()` gain a `plan_envelope` parameter that requires every
   member manifest to already be sealed before any one of them can be
   granted, or is atomicity enforced later at commit time via a new
   `commit_plan()` engine method that either commits every member effect
   or rolls back (invoking Phase 7's eventual Compensation Manifests, or
   today's existing `compensate()` path) if any one fails? The latter is
   likely more honest given this protocol's existing "compensation is
   best-effort, never guaranteed" stance (invariant #25) -- an atomic
   plan cannot promise true multi-effect atomicity across independent
   external systems without a two-phase-commit-capable adapter, which no
   reference adapter implements. State the real guarantee precisely
   rather than implying database-style atomicity that doesn't exist.
3. Reuse Phase 4's `RoleAssignment`/`SeparationOfDutyPolicy` machinery
   for plan-level separation of duty (e.g. "no principal may approve
   more than N members of one plan") rather than inventing a parallel
   mechanism, following the same "generalize, don't duplicate" principle
   Phase 4 itself followed relative to Phase 3.
4. Extend the Action Passport (or introduce a `PlanPassport`) to record
   which members of a plan committed, which failed, and whether
   compensation was attempted for any that failed after others
   succeeded -- the honest, partial-failure story a real atomic-looking
   operation across independent systems actually has.
5. CLI/API surface: a `karmasakshi plan authorize <plan_id>` /
   `karmasakshi plan commit <plan_id>` pairing and `POST
   /plans/{id}/authorize` / `POST /plans/{id}/commit`; avoid duplicating
   the existing single-manifest `authorize()`/`commit()` logic --
   the plan-level methods should orchestrate calls to the existing
   per-manifest methods, not reimplement their checks.
