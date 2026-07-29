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
| 5. Causal effect graphs | **Implemented (proof metadata)** | Signed deterministic DAG, bounded validation, API and passport ancestry; no implicit execution authority |
| 6. Atomic plan authorization / decision envelopes | **Implemented** | See below |
| 7. Compensation manifests | **Implemented** | Separate Compensation Passports; see below |
| 8. Saga orchestration | **Implemented** | Multi-grant topo orchestration; see below |
| 9. Independent witness quorum | **Implemented** | See below |
| 10. Evidence quality and provenance | **Implemented** | See below |
| 11. Deep delegation revocation | **Implemented** | Lineage walk at commit; see below |
| 12. Authority budgets | **Implemented** | Single-process atomic ledger; see below |
| 13. Durable lifecycle storage | **Implemented** | SQLite single-node lifecycle store; see below |
| 14. Distributed audit journal | **Implemented** | AuditBackend contract + optional Redis sink; no consensus claims |
| 15. Transactional outbox | **Implemented** | Intent vs confirmed; see below |
| 16. Production signer interface | **Implemented** | Signer protocol + local/emulated backends; no real KMS |
| 17. Trusted adapter registry | **Implemented** | Versioned allow-list; fail-closed; see below |
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

## Phase 5 implementation: signed causal effect graphs

**Status:** Implemented as an additive proof-metadata layer.

**Files:** `src/karmasakshi/causal/`, API state/routes/schemas, Action
Passport model/generator/rendering, focused unit/integration tests, README,
CHANGELOG and `docs/causal-effect-graphs.md`.

**Security invariants:** every edge binds exact parent and child hashes and
must have a valid signature; graph identity is deterministic and independent
of input ordering; missing nodes, duplicate links, self-links and cycles fail
closed; size and depth are bounded; graph membership never grants authority.

**Known limitations:** reference API storage is process-local; graph
relationships are evidence only and do not propagate authorization,
revocation, ordering or failure state.

**Verification commands:** `ruff format --check .`, `ruff check .`,
`mypy src`, `bandit -q -r src`, `pytest -q` (**516 passed, 6 skipped**),
`python -m build`, and `twine check dist/*` all passed. The six skips
remain the explicit Redis-only tests because no local Redis server was
available.

**Commit SHA:** `63bea0f` — signed causal effect graphs implementation.

## Phase 6: Atomic plan authorization / constrained decision envelopes

**Status: implemented.**

### Files changed

- Added: `src/karmasakshi/envelope/{__init__,constraints,model,sealing,substitution,plan}.py`
- Added: `src/karmasakshi/cli/envelope_cmd.py`
- Added: `docs/decision-envelopes.md`
- Added: `tests/unit/test_decision_envelopes.py`,
  `tests/property/test_decision_envelope_properties.py`,
  `tests/adversarial/test_decision_envelope_gaming.py`
- Modified: `src/karmasakshi/errors/__init__.py` (envelope + atomic-plan errors),
  `src/karmasakshi/grants/{model,issuer}.py` (`decision_envelope_hash` /
  `causal_graph_hash`, mutual exclusivity),
  `src/karmasakshi/engine/core.py` (`authorize_with_envelope`,
  `authorize_plan`, `commit` re-verification),
  `src/karmasakshi/api/{schemas,state,routes}.py`,
  `src/karmasakshi/cli/{app,grant_cmd,execute_cmd,workspace}.py`,
  `src/karmasakshi/passports/{model,generator,render}.py`
- Docs updated: `docs/security-model.md` (invariants #39–#42),
  `docs/execution-grants.md`, `docs/limitations.md`, `README.md`,
  `CHANGELOG.md`

### Design decisions

- **Authorization still binds a concrete sealed manifest** in this phase,
  plus either an envelope or a causal graph. Flexible “authorize envelope
  first, substitute later, then execute” is deferred; substitution is
  shipped as deterministic library logic so later wiring cannot invent
  non-deterministic rules.
- **Envelope XOR graph on the grant.** A grant may not carry both
  `decision_envelope_hash` and `causal_graph_hash`. An envelope may itself
  pin a `causal_graph_hash` inside its signed payload.
- **Commit re-verifies** the bound envelope/graph the same way policy
  bundles are re-verified (fail closed on missing/swapped/tampered/
  expired/out-of-constraint).

### Security invariants added

- **#39**: Envelope XOR causal-graph plan-level binding on a grant.
- **#40**: Envelope-bound grants fail closed at commit without the matching
  fitting envelope.
- **#41**: Plan-bound grants fail closed unless the sealed manifest is a
  verified node of the matching graph.
- **#42**: Agents cannot issue Decision Envelopes; substitution/narrowing
  are deterministic.

### Verification commands

```bash
ruff check .
ruff format --check .
mypy src
bandit -r src/karmasakshi
python -m pytest -q
python -m build && python -m twine check dist/*
pip-audit
```

Results at the time of this commit: `ruff check`/`ruff format --check`/
`mypy src`/`bandit` clean (no new assert findings); `pytest -q` →
**543 passed, 6 skipped** (Redis-only); `build`/`twine check` clean;
`pip-audit` → same 1 known dev-only `pytest` CVE as prior phases
(unresolved).

### Coverage follow-up (CI gate)

PR #20 initially failed `CI / Coverage` (~85%). Follow-up commit adds:

- `tests/unit/test_decision_envelope_coverage.py` — constraint/model/seal/
  substitution/plan edge paths
- `tests/integration/test_cli_envelope.py` — CLI create/verify/substitute +
  graph pin path (also lifts `graph_cmd` coverage)
- `tests/integration/test_api_decision_envelopes.py` — HTTP create/get/
  substitute + approve/execute binding
- `constraints.py` round-trip fix: range kinds reject only non-`None`
  `exact_value` so JSON rehydration of `exact_value: null` remains valid

Local gates after follow-up: **559 passed, 6 skipped**; coverage
**90.55%** (`--cov-fail-under=90`); ruff/mypy/bandit/build/twine clean.

### Commit SHAs / PR

- `57371d7` — Phase 6: Atomic plan authorization / constrained decision envelopes
- `93bdaf9` — Phase 6 coverage follow-up (90.55% local; CLI/API/unit +
  constraint JSON round-trip fix)
- PR: https://github.com/nishanttyagi28/karmasakshi-protocol/pull/20

### Session baseline (this agent, before Phase 6)

Confirmed Phase 5 on `main` at `eb94aab`. Baseline suite:
**516 passed, 6 skipped**.

## Exact next executable step

**Phase 18: Adapter conformance kit.** Deterministic conformance tests
for EffectAdapter contract honesty (prepare/commit/verify/compensate
invariants) against reference and third-party adapters.

## Resumable checkpoint

- last merged phase on main: Phase 16 (`f94c861`, PR #31)
- current branch: `cursor/phase17-trusted-adapter-registry-ffca`
- open PR: https://github.com/nishanttyagi28/karmasakshi-protocol/pull/32
- latest green commit (local): `604b6fb`
- test counts: **683 passed, 8 skipped**; coverage **90.18%**
- quality gates: ruff / mypy / bandit / build / twine clean
- exact next phase: 18 — Adapter conformance kit

## Phase 17: Trusted adapter registry

**Status: implemented on branch.**

### What landed

- `AdapterCapability`, `TrustedAdapterRegistry`, `build_reference_registry`
- Optional `EngineContext.adapter_registry`; prepare/commit/verify/compensate gates
- API + public demo wire the reference registry by default
- Invariants #65–#67; docs: `docs/trusted-adapter-registry.md`

### Design decisions

- Exact version pins only (no semver ranges / no plugin discovery)
- Omitting the registry preserves Phases 1–16 behavior
- Process-local allow-list; not multi-node consensus
- Compensation commit checks adapter trust, not `.compensate` effect-type
  suffix (grant still binds allowed effect types)

### Verification (this branch)

- `pytest`: **683 passed, 8 skipped**; coverage **90.18%** (branch)
- `ruff check` / `ruff format --check`: clean
- `mypy src`: clean
- `bandit -r src/karmasakshi`: clean
- `python -m build` + `twine check`: PASS

## Phase 16: Production signer interfaces

**Status: implemented on branch (PR #31).**

### What landed

- `Signer` protocol; `LocalDevSigner`; `EmulatedKmsSigner` (local only)
- `require_signer_env` fail-closed
- Docs: `docs/production-signers.md`

### Design decisions

- No AWS/GCP/HSM SDKs; emulator is local Ed25519 with a fake `kms_key_ref`
- Existing `SigningKey` remains supported


## Phase 15: Transactional outbox and recovery

**Status: implemented on branch (PR #30).**

### Local gates

**662 passed, 8 skipped**; coverage **90.01%**.

### What landed

- `karmasakshi.outbox`: `OutboxEntry` / `OutboxStore` + memory/SQLite
- Engine records PENDING after COMMITTING; confirms or abandons honestly
- Adapter exceptions leave PENDING for `recover_ambiguous_commit`
- CLI/API open `outbox.db`
- Docs: `docs/transactional-outbox.md`

### Design decisions

- Not exactly-once; pending != verified
- Single-node SQLite; no consensus claims


## Phase 14: Distributed audit journal abstraction

**Status: implemented on branch.**

### What landed

- `AuditBackend` extracted to `audit/base.py` (`runtime_checkable`)
- Optional `RedisAuditBackend` (Lua `LLEN+1 == sequence` then RPUSH)
- Docs: `docs/audit-journal.md`; storage-semantics + limitations updated
- Tests: protocol/SQLite conflict unit tests; Redis tests skip without Redis

### Design decisions

- No Raft/etcd claims — Redis EVAL atomicity only
- Journal process lock remains process-local
- CLI/API defaults stay on SQLite


## Phase 13: Durable lifecycle storage

**Status: merged to main (`bee60d8`, PR #28).**

### What landed

- `LifecycleStore` protocol + memory/SQLite backends; engine write-through
- CLI/API `lifecycle.db`; invariant #64
- Docs: `docs/durable-lifecycle-storage.md`

## Phase 12: Atomic authority budgets

**Status: implemented on branch.**

### What landed

- `karmasakshi.budget`: `AuthorityBudget` (monetary/count),
  `InMemoryBudgetLedger` (atomic reserve/release/commit/consume),
  `resolve_budget_consume_amount` / `require_budget`
- `ExecutionGrant.authority_budget_id` signed binding; issuer + attenuation
- `EngineContext.budget_ledger`; authorize paths bind; `commit()` reserves
  before adapter, commits on success, releases on failure/idempotent replay
- Invariants **#60–#63**
- Docs: `docs/authority-budgets.md`

### Design decisions

- Distinct from `scope.max_amount` (per-grant attenuation vs shared ledger)
- Monetary consume uses `manifest.estimated_cost` only — never invent amount
- Single-process ledger only; durable multi-node deferred to Phase 13+
- Delegation inherits parent budget; drop/swap treated as widening

### Local gates

**641 passed, 6 skipped**; coverage **90.19%** (`--cov-fail-under=90`);
ruff/mypy/bandit/build/twine clean.

## Phase 11: Deep delegation revocation

**Status: implemented on branch.**

### What landed

- GrantStore lineage API on memory/SQLite/Redis
- `assert_no_revoked_ancestors` (depth/cycle/uncertainty fail-closed)
- Engine records lineage on authorize/delegate; commit walks ancestors
- Invariants **#58–#59**
- Docs: `docs/delegation.md` updated

## Phase 10: Evidence quality and provenance

**Status: implemented on branch.**

### What landed

- `karmasakshi.evidence`: `EvidenceKind` ladder, `EvidenceRecord`,
  `EvidencePolicy`, `evaluate_evidence_quality` /
  `assert_evidence_quality`, `evidence_from_outcome_proof`
- Engine: `evaluate_evidence`, `assert_evidence_quality`
- Passport optional evidence fields
- Invariants **#54–#57**
- Docs: `docs/evidence-quality.md`

### Design decisions

- Default `min_kind=adapter_reobserve` so provider success echoes alone
  cannot satisfy VERIFY/PROVE evidence policy
- Adapters not auto-emitting EvidenceRecords yet; callers wrap
  OutcomeProof with an honest kind
- Sealed evidence-policy bundles deferred

## Phase 9: Independent witness quorum

**Status: implemented on branch.**

### What landed

- `karmasakshi.witness`: `WitnessStatement`, `WitnessPolicy`,
  `evaluate_witness_quorum`, signing gates
- Engine: `evaluate_witnesses`, `prove_with_witness_quorum`
- CLI: `karmasakshi witness sign|evaluate`
- API: `/manifests/{id}/witnesses` (+ evaluate)
- Passport optional fields: `witness_set_hash`, `witness_policy_hash`,
  `witness_quorum_satisfied`, `accepted_witness_ids`
- Invariants **#50–#53**
- Docs: `docs/witness-quorum.md`

### Design decisions

- Witnesses are VERIFY/PROVE-time observations, not AUTHORIZE-time
  approvals
- Statements bind `witness_policy_hash` of a plain `WitnessPolicy`
  (sealed `witness.v1` bundles deferred)
- PROVE remains passport/evidence surface — no new lifecycle state
- Agents, actor, and subject fail closed by default

## Phase 8: Durable saga orchestration

**Status: implemented on branch.**

### What landed

- `karmasakshi.saga`: deterministic topo order, `SagaPlan`/`SagaRun`,
  fail-closed step machine
- Engine: `begin_saga`, `authorize_saga_step`, `commit_saga_step`,
  `verify_saga_step`, `recover_saga_step`, `record_saga_compensation`
- Invariants **#46–#49**
- Docs: `docs/saga-orchestration.md`

### Design decisions

- Multi-grant only (one grant per sealed step); multi-node single-grant
  remains deferred
- AMBIGUOUS blocks blind re-commit; recovery re-observes first
- Compensation recording uses Phase 7 status triad in reverse order;
  terminal saga status after compensation is `failed_partial` (never
  claimed as atomic rollback)
- Durability = audit events + process-local run state (Phase 13 for
  shared durable saga storage)

## Phase 7: Compensation manifests / Compensation Passports

**Status: implemented on branch `cursor/phase7-compensation-passports-ffca` (`1701f6d`).**

### What landed

- `karmasakshi.compensation`: status triad, `build_compensation_manifest`
  (binds `original_manifest_hash`), `CompensationPassport` builder that
  never mutates Action Passports
- Engine: `prepare_compensation`, `authorize_compensation`,
  `commit_compensation` (grant-gated; calls `adapter.compensate` on the
  original). Legacy `compensate()` retained.
- CLI: `karmasakshi compensation prepare|authorize|execute|passport`
- API: `/manifests/{id}/compensation/...` prepare/authorize/execute/passport
- Invariants **#43–#45**
- Docs: `docs/compensation-manifests.md`

### Design decisions

- Authorized compensation consumes a grant bound to the *compensation*
  sealed hash, then executes via `adapter.compensate(original, ...)`,
  not `adapter.commit` on the compensation manifest.
- Action Passport pointer fields only; Compensation Passport is the
  authoritative compensation record.

### Verification

Local: **571 passed, 6 skipped**; coverage **90.15%**; ruff/mypy/bandit/
build/twine clean.

## Preserved Phase 5 design notes


The following notes were used to scope Phase 5:

1. Today `EffectManifest.parent_manifest_id` is a single unsigned string
   field -- no verification that a claimed parent actually exists, was
   sealed, or that the claimed causal link is real. Phase 5 should
   introduce a signed `CausalLink` (or similar) binding a child
   manifest's hash to its parent's hash, verified the same way a `Seal`
   is verified, so a chain of manifests can be walked and independently
   proven, not just asserted.
2. Model the graph structure explicitly: a `CausalEffectGraph` type
   (nodes = manifest hashes, edges = signed causal links) with cycle
   detection (a manifest can never causally depend on its own effect)
   and a bound on graph size/depth (resource protection, consistent with
   `ApprovalPolicy.max_statements_considered` and
   `RoleAssignment.MAX_ROLE_ASSIGNMENTS`).
3. Decide and document precisely what a causal link changes about
   authorization/execution -- e.g. should a parent's revocation
   propagate to children automatically (this would generalize the
   existing one-hop delegation-revocation propagation in `commit()` to
   the causal-graph case), or is Phase 5 initially just a verifiable
   *record* of causality (PROVE-time value) without new enforcement
   (mirroring how Phase 1's Effect Intelligence Engine started
   advisory-only)? The honest, incremental choice is likely the latter
   first, enforcement later -- state this explicitly rather than
   quietly deciding one way.
4. Extend the Action Passport to include the causal chain (parent
   hashes, verified or not) so a full multi-step operation (e.g. "refund
   -> compensating ledger adjustment") can be proven as one coherent
   causal story, not just as isolated individually-verified effects.
5. CLI/API surface: likely a read-only `karmasakshi manifest graph
   <manifest_id>` inspection command and a `GET
   /manifests/{id}/causal-graph` endpoint; avoid adding new write paths
   beyond what's needed to record a signed causal link at `prepare()`/
   `seal()` time.
