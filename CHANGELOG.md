# Changelog

All notable changes to this project are documented in this file. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] - extreme-v2 in progress

### Added

- **Effect Intelligence Engine** (`karmasakshi.intelligence`): a
  deterministic, versioned risk-scoring engine over `EffectManifest` +
  `IntelligencePolicy` + `AssessmentFacts`, producing a structured,
  audit-recorded `EffectAssessment` (score, risk level, named signals,
  recommendation, required approvals/witness quorum/verification
  strength). No LLM in the loop; pure, reproducible arithmetic. Integrated
  into the engine (`KarmaSakshiEngine.assess()`), the CLI
  (`karmasakshi assess`), the API (`POST /manifests/{id}/assess`, `GET
  /manifests/{id}/assessment`), and the Action Passport. **Advisory only
  in this release** -- see [docs/effect-intelligence.md](docs/effect-intelligence.md)
  for exactly what is and is not enforced. See
  [docs/extreme-v2-build-status.md](docs/extreme-v2-build-status.md) for
  the full build ledger and remaining phases of this program.
- **Signed policy bundles** (`karmasakshi.policy`): a cryptographic
  envelope (`PolicyBundle`/`SealedPolicyBundle`, sealed/verified the same
  way `EffectManifest` is) around a versioned `IntelligencePolicy`, with
  an explicit effective window. `ExecutionGrant.policy_bundle_hash` binds
  a grant to one exact policy bundle at authorization time;
  `engine.commit()` requires the identical bundle (by hash) to be
  re-verified before executing, so a policy edit or swap after approval
  can never silently change what a grant authorizes (new invariant #31).
  An agent principal cannot be a policy bundle's issuer (invariant #32,
  mirroring invariant #30). Integrated into the CLI (`karmasakshi policy
  create/sign/verify`, `--policy-bundle-id` on `grant issue`/`execute`)
  and the API (`POST /policy/bundles`, `--policy_bundle_id` on
  `/approve`/`/execute`). See [docs/policy-bundles.md](docs/policy-bundles.md).
- **Multi-party (M-of-N) authorization** (`karmasakshi.approval`): signed
  `ApprovalStatement`s (approve/dissent, bound to one exact manifest +
  approval-policy-bundle pair) evaluated deterministically and
  order-independently against a versioned `ApprovalPolicy` (required
  approval count, required roles, no-self-approval, no-executor-approval,
  dissent veto, cooling-off period) via
  `KarmaSakshiEngine.authorize_with_quorum()`. A grant issued this way is
  structurally impossible without a satisfied quorum (invariant #33); an
  agent can never sign or count as an approval (invariant #34); the
  proposer and executing subject can never satisfy their own grant's
  quorum (invariant #35); evaluation is deterministic regardless of
  statement order, including conflicting statements from the same
  approver (invariant #36). Additive: the original single-issuer
  `authorize()` is unchanged. Integrated into the CLI (`karmasakshi policy
  create-approval`, `karmasakshi approve`, `karmasakshi approvals
  inspect`, `karmasakshi grant issue-with-quorum`) and the API (`POST
  /policy/approval-bundles`, `/manifests/{id}/approvals[/evaluate]`,
  `/manifests/{id}/approve-with-quorum`). See
  [docs/multi-party-authorization.md](docs/multi-party-authorization.md).
- **Separation of duties** (`karmasakshi.duty`): an explicit, closed set
  of protocol roles (`ProtocolRole`: proposer, resolver, assessor,
  sealer, approver, executor, verifier, witness, compensator, auditor), a
  structural per-manifest `RoleAssignment`, and a versioned, signable
  forbidden-role-pair matrix (`SeparationOfDutyPolicy`, wrapped in the
  same signed `PolicyBundle` envelope as the other policy types,
  `policy_type="separation.v1"`). `KarmaSakshiEngine.authorize()` and
  `.authorize_with_quorum()` take optional `separation_policy_bundle` and
  `role_assignment` arguments; a violation raises
  `SeparationOfDutyViolationError` before a grant is ever issued
  (invariant #37), and evaluation is deterministic and order-independent
  (invariant #38). Additive: omitting `separation_policy_bundle` leaves
  both entry points behaving exactly as before this phase. The Action
  Passport gained a `role_participation` field, populated automatically
  from the audit trail. Integrated into the CLI (`karmasakshi policy
  create-separation`, `--separation-policy-bundle-id`/`--role` on `grant
  issue`/`grant issue-with-quorum`) and the API (`POST
  /policy/separation-bundles`, the same two optional fields on
  `/approve` and `/approve-with-quorum`). See
  [docs/separation-of-duties.md](docs/separation-of-duties.md).
- **Causal effect graphs** (`karmasakshi.causal`): signed `CausalLink`s
  (`triggers`/`compensates`/`depends_on`/`supersedes`) between manifest
  hashes, assembled into a `CausalEffectGraph` with iterative (stack-safe)
  cycle detection and independent per-link signature re-verification via
  `verify_causal_graph()`. **Advisory only**, exactly like Phase 1's
  Effect Intelligence Engine: `authorize()`/`authorize_with_quorum()`/
  `commit()` never read or enforce a causal graph, so no new numbered
  security invariant was added. `KarmaSakshiEngine.record_causal_link()`
  and `.verify_causal_graph()` are audited side-channel steps, like
  `assess()`. Unlike every other signed artifact in this protocol, an
  agent principal may sign a causal link -- it is a factual claim, not an
  authorization decision. The Action Passport gained
  `causal_ancestor_hashes`/`causal_graph_verified`/`causal_graph_reason`
  fields. Integrated into the CLI (`karmasakshi causal record`,
  `karmasakshi causal verify`, and `karmasakshi passport` automatically
  includes the workspace's causal graph) and the API (`POST
  /causal-links`, `GET /causal-links`, `POST /causal-links/verify`). See
  [docs/causal-effect-graphs.md](docs/causal-effect-graphs.md).

## [0.1.0] - 2026-07-27

Initial feature-complete reference implementation of protocol schema
version `1.0`.

### Added

- Core protocol: `EffectManifest`, canonical serialization/hashing,
  `Seal`/`SealedManifest`, `ExecutionGrant`, Ed25519 signing/verification
  with a rotatable keyring.
- Lifecycle state machine (`PROPOSED` → `PREPARED` → `SEALED` →
  `AUTHORIZED` → `COMMITTING` → `COMMITTED` → `VERIFIED`, plus `FAILED`,
  `REVOKED`, `EXPIRED`, `COMPENSATING`, `COMPENSATED`) and the
  `KarmaSakshiEngine` orchestrator enforcing all 30 documented security
  invariants (see `docs/security-model.md`).
- Storage backends: in-memory, SQLite (durable, single-node), and Redis
  (distributed, Lua-script atomic consumption).
- Delegation with attenuation (parent→child narrowing, multi-hop chain
  verification, one-hop revocation propagation at commit time).
- Append-only, hash-chained audit journal (in-memory and SQLite backends)
  and Action Passport generation (JSON/Markdown/HTML).
- Three reference Effect Adapters: SQLite row insert/update/delete
  (parameterized SQL, optimistic concurrency), an email sandbox (never
  sends real email), and a deterministic payment simulator (never moves
  real money; includes injectable failure and ambiguous-timeout modes).
- Optional LangGraph integration: pause-for-authorization, resume, commit,
  verify, with the signing key kept out of graph state/checkpoints.
- Optional AgentEval bridge: versioned, neutral regression-fixture export.
- CLI (`karmasakshi`): init, key management, prepare/seal, grant
  issue/verify/delegate/revoke/inspect, execute/verify/compensate, audit
  list/show/verify, passport generation, a 15-scenario deterministic demo
  suite, and a doctor command.
- Optional FastAPI control plane and a server-rendered local console,
  with fail-closed bearer-token authentication and an emergency kill
  switch.
- 272+ tests (unit, integration, property-based via Hypothesis, and
  adversarial) plus documentation covering architecture, protocol spec,
  the security model, threat model, storage semantics, crash recovery,
  adapter authoring, and honest limitations.

### Known limitations

See [docs/limitations.md](docs/limitations.md). Highlights: no
third-party security audit; Redis backend tests only run against a real
reachable Redis instance; the AgentEval bridge is a neutral export format,
not a verified-compatible schema implementation; SQLite storage is
single-node only.
