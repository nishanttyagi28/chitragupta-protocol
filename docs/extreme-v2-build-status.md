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
| 3. Multi-party (M-of-N) authorization | Not started | |
| 4. Separation of duties (explicit roles) | Not started | |
| 5. Causal effect graphs | Not started | `parent_manifest_id` remains a single unsigned string field, unchanged from v0.1 |
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

Recorded after this slice's PR is opened and merged (see repository
history / PR list for the exact SHAs and PR number -- this ledger entry
is completed as part of that PR, matching the pattern established for
Phase 1).

## Exact next executable step

**Phase 3: Multi-party (M-of-N) authorization.** Concretely:

1. Add `ApprovalStatement` (one principal's signed yes/no on a specific
   `manifest_hash` + `policy_bundle_hash` pair, with expiry) and
   `ApprovalSet` (a collection of statements) domain models, mirroring
   the `Seal`/`PolicyBundleSeal` sign/verify pattern a third time.
2. Add `ApprovalPolicy` (quorum rules: N-of-M, named-role requirements
   such as "finance + security", no-self-approval, proposer/executor
   exclusion) -- this is a natural companion payload type for the
   `PolicyBundle` envelope built in Phase 2 (`policy_type =
   "approval.v1"`), reusing the same signed-bundle infrastructure rather
   than inventing a new one.
3. Extend `engine.authorize()` (or add a new `engine.authorize_with_quorum()`
   entry point, preserving the existing single-issuer `authorize()` for
   backward compatibility per the mission's explicit requirement) to
   accept an `ApprovalSet`, verify each statement (signature, expiry,
   manifest/policy binding, no duplicate/self approvers), evaluate it
   against the bound `ApprovalPolicy`'s quorum rule, and only then issue
   the grant.
4. This is also the natural point to read
   `EffectAssessment.required_human_approvals`/
   `required_witness_quorum` from Phase 1 and make it feed the quorum
   requirement -- turning the advisory recommendation into a structural
   requirement for the first time, now that both the policy (Phase 2)
   and the approval set (Phase 3) are cryptographically pinned.
5. Extend the CLI (`karmasakshi approve`/`karmasakshi approvals inspect`)
   and API accordingly.
