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
- **Signed causal effect graphs** (`karmasakshi.causal`): signed links
  bind exact parent and child manifest hashes into deterministic DAGs.
  Graph construction rejects missing endpoints, duplicate links,
  self-links, cycles, excessive depth and excessive size. Action
  Passports carry verified graph ancestry; the API exposes create and
  inspect endpoints. Graphs are proof metadata in schema 1.x and do not
  implicitly authorize or order execution. See
  [docs/causal-effect-graphs.md](docs/causal-effect-graphs.md).
- **Constrained Decision Envelopes and atomic plan authorization**
  (`karmasakshi.envelope`): signed parameter constraints (`exact` /
  `enum` / `integer_range` / `monetary_range`), deterministic
  substitution, envelope narrowing that fails closed on widening, and
  grant bindings to either a Decision Envelope *or* a sealed causal
  graph (never both). `authorize_with_envelope` /
  `authorize_plan` bind the hashes; `commit()` re-verifies them
  (invariants #39–#42). Flexible “authorize envelope first, substitute
  later” execution wiring is deferred. See
  [docs/decision-envelopes.md](docs/decision-envelopes.md).
- **Compensation manifests and Compensation Passports**
  (`karmasakshi.compensation`): compensation is a separately authorized
  effect that binds `original_manifest_hash`, consumes its own grant, and
  emits a Compensation Passport that never mutates the Action Passport
  (invariants #43–#45). `commit_compensation` calls `adapter.compensate`
  on the original effect after grant verification. Legacy
  `engine.compensate()` / `karmasakshi compensate` remain. See
  [docs/compensation-manifests.md](docs/compensation-manifests.md).
- **Durable saga orchestration** (`karmasakshi.saga`): deterministic
  topo-ordered multi-grant runs over a verified causal graph; at-most-once
  steps; AMBIGUOUS blocks blind retry; reverse Phase 7 compensation
  recording (invariants #46–#49). Not exactly-once; not multi-node
  single-grant. See [docs/saga-orchestration.md](docs/saga-orchestration.md).
- **Independent witness quorum** (`karmasakshi.witness`): signed
  post-COMMIT observations distinct from AUTHORIZE-time approvals;
  agents/actor/subject cannot satisfy quorum by default; digest and
  policy-hash binding; deterministic `witness_set_hash` (invariants
  #50–#53). Engine `prove_with_witness_quorum`, CLI `witness`, API
  `/witnesses`. See [docs/witness-quorum.md](docs/witness-quorum.md).
- **Evidence quality and provenance** (`karmasakshi.evidence`): typed
  `EvidenceRecord` ladder (provider claim → adapter re-observe →
  independent ledger → witness), freshness bounds, fail-closed
  evaluation (invariants #54–#57). See
  [docs/evidence-quality.md](docs/evidence-quality.md).
- **Deep delegation revocation** (`karmasakshi.delegation.revocation`):
  grant stores record lineage; `engine.commit()` walks all ancestors and
  fails closed on revoked ancestors or missing lineage (invariants
  #58–#59). See [docs/delegation.md](docs/delegation.md).
- **Atomic authority budgets** (`karmasakshi.budget`): shared monetary /
  count ledgers bound via `ExecutionGrant.authority_budget_id`;
  `commit()` atomically reserves/consumes (invariants #60–#63).
  Single-process ledger only. See
  [docs/authority-budgets.md](docs/authority-budgets.md).
- **Durable lifecycle storage** (`LifecycleStore`): optional SQLite
  single-node write-through for current lifecycle state; audit remains
  the tamper-evident record. See
  [docs/durable-lifecycle-storage.md](docs/durable-lifecycle-storage.md).
- **Distributed audit journal abstraction**: stabilized `AuditBackend`
  protocol; optional `RedisAuditBackend` with Lua sequence-checked
  append (not Raft/etcd). See [docs/audit-journal.md](docs/audit-journal.md).
- **Production signer interfaces** (`Signer` / `LocalDevSigner` /
  `EmulatedKmsSigner`): honest KMS-shaped local emulators; no real
  cloud KMS. See [docs/production-signers.md](docs/production-signers.md).
- **Transactional outbox** (`karmasakshi.outbox`): durable commit intent
  (`pending` / `confirmed` / `abandoned`) with crash-recovery wiring.
  Not exactly-once. See [docs/transactional-outbox.md](docs/transactional-outbox.md).
- **Trusted adapter registry** (`TrustedAdapterRegistry`): versioned
  `(adapter_id, adapter_version)` allow-list with fail-closed unknown /
  revoked / undeclared-effect-type checks when configured (invariants
  #65–#67). Process-local; no dynamic plugins. See
  [docs/trusted-adapter-registry.md](docs/trusted-adapter-registry.md).
- **Adapter conformance kit** (`run_adapter_conformance`): structural
  contract checks including forged-success rejection before commit
  (invariant #68). Not a cloud-provider certification. See
  [docs/adapter-conformance.md](docs/adapter-conformance.md).
- **Multi-tenant control plane** (`Tenant` / `TenantRegistry` /
  `MultiTenantControlPlane`): process-local org isolation; policy
  tenant binding on `EngineContext.tenant_id` (invariants #69–#70). See
  [docs/multi-tenant.md](docs/multi-tenant.md).
- **Resource / DoS protection** (`ResourceProtectionMiddleware`):
  Content-Length and per-client rate ceilings on the control-plane API
  (invariants #71–#72). Process-local. See
  [docs/resource-protection.md](docs/resource-protection.md).
- **Adversarial / fuzz expansion** (Phase 21): Hypothesis properties and
  gaming tests for tenant isolation and resource protection. See
  [docs/adversarial-fuzz.md](docs/adversarial-fuzz.md).
- **Bounded lifecycle state-machine model checking** (Phase 22):
  `check_lifecycle_model()` exhausts a small transition graph; not a
  theorem prover. See
  [docs/state-machine-model-checking.md](docs/state-machine-model-checking.md).
- **Action Passport V2** (`action_passport.v2` / schema `2.0`): additive
  versioned passport with deterministic `outcome_status`, content
  `passport_hash`, and optional `tenant_id` (invariant #73). V1 remains
  default. See [docs/action-passport-v2.md](docs/action-passport-v2.md).
- **Portable Evidence Packs** (`karmasakshi.portable`, `evidence_pack.v1`
  / schema `1.0`): a self-contained, offline-verifiable bundle (Action
  Passport V2 + sealed manifest + grant + audit slice + public keys) that
  a recipient can independently re-verify with no access to the original
  store, database, or live keyring (invariant #74). CLI
  `evidence-pack build|verify`; API `GET /passports/{id}/evidence-pack`,
  unauthenticated `POST /evidence-pack/verify`. See
  [docs/portable-evidence.md](docs/portable-evidence.md).
- **Observability** (`karmasakshi.observability`): a neutral, versioned
  lifecycle event (`ObservabilityEvent`) and pluggable sinks
  (in-memory, JSON-Lines file). Advisory only — `engine.observe()` never
  gates a lifecycle transition, is never written to the audit journal,
  and a failing sink never propagates. See
  [docs/observability.md](docs/observability.md).


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
