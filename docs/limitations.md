# Honest Limitations

This is a feature-complete reference implementation of an explicitly
versioned, experimental protocol (schema `1.0`). It is **not**:

- Independently security-audited.
- Certified for any compliance regime (PCI-DSS, SOC 2, etc.).
- "Production proven" — it has not run in any real production deployment.
- A guarantee of correctness for any specific real-world payment, email,
  or database provider — the three shipped adapters are reference/demo
  implementations, not connectors to Stripe, SendGrid, Postgres, or any
  other real product.

## Specific, itemized limitations

- **SQLite is single-node.** Both `SQLiteGrantStore` and
  `SQLiteAuditBackend` serialize writers at the file level and are safe
  across processes on one machine, not across machines. Use
  `RedisGrantStore` for distributed grant consumption; there is no
  distributed audit consensus layer shipped. Optional `RedisAuditBackend`
  (Phase 14) provides shared Redis append with Lua sequence checks — not
  Raft/etcd. Default CLI/API still use SQLite. See
  [docs/audit-journal.md](audit-journal.md).
- **Redis test coverage is environment-dependent.** The Redis backend's
  test suite is collected but every test skips (with an explicit reason)
  if no Redis instance is reachable. In the environment this branch was
  built in, that was the case — the Redis backend's logic is implemented
  and unit-testable in isolation, but was not exercised against a live
  Redis server as part of this build. Run `docker compose up redis` and
  re-run `pytest -m redis` to exercise it.
- **Multi-hop delegation revocation walks recorded lineage at commit
  time** (extreme-v2 Phase 11). Grants issued through the engine record
  parent pointers in the grant store. Missing intermediate lineage fails
  closed (revocation uncertainty). Cascading “mark all descendants
  revoked” is not implemented — descendants are blocked at commit when an
  ancestor is revoked. See [docs/delegation.md](delegation.md).
- **Authority budgets are single-process** (extreme-v2 Phase 12).
  `InMemoryBudgetLedger` provides atomic reserve/commit under a process
  lock; there is no durable multi-node budget ledger yet.
  See [docs/authority-budgets.md](authority-budgets.md).
- **Lifecycle convenience state can be SQLite-durable** (extreme-v2
  Phase 13) via `lifecycle.db`, but remains single-node and does not
  replace the audit hash chain. See
  [docs/durable-lifecycle-storage.md](durable-lifecycle-storage.md).
- **Compensation is best-effort, never guaranteed.** Some effects
  (irreversible ones by classification, or provider states that don't
  support cancellation, like a settled payment) honestly refuse
  compensation rather than pretending to roll back. Extreme-v2 Phase 7
  adds a separately authorized compensation path and Compensation
  Passports ([docs/compensation-manifests.md](compensation-manifests.md));
  that path still cannot invent provider rollback that does not exist.
- **No real cloud KMS/HSM.** Phase 16 adds `Signer` / `LocalDevSigner` /
  `EmulatedKmsSigner` (local Ed25519 only). See
  [docs/production-signers.md](production-signers.md).
- **Trusted adapter registry is process-local** (extreme-v2 Phase 17).
  Exact `(adapter_id, adapter_version)` allow-list with fail-closed
  unknown/revoked/undeclared-effect-type checks when configured. Not a
  multi-node consensus store. See
  [docs/trusted-adapter-registry.md](trusted-adapter-registry.md).
- **Adapter conformance kit is structural** (extreme-v2 Phase 18). Passing
  does not certify a live cloud provider. See
  [docs/adapter-conformance.md](adapter-conformance.md).
- **Multi-tenant isolation is process-local** (extreme-v2 Phase 19).
  Per-tenant `ApiState` partitions and policy tenant binding; not a
  distributed directory. See [docs/multi-tenant.md](multi-tenant.md).
- **API resource protection is process-local** (extreme-v2 Phase 20).
  Body-size and per-client rate ceilings; not a WAF. See
  [docs/resource-protection.md](resource-protection.md).
- **Bounded lifecycle model checking is not formal verification**
  (extreme-v2 Phase 22). `check_lifecycle_model()` exhausts a small graph;
  it is not a theorem prover. See
  [docs/state-machine-model-checking.md](state-machine-model-checking.md).
- **Action Passport V2 is additive** (extreme-v2 Phase 23). Default
  emission remains v1; V2 `passport_hash` is content-binding, not a
  separately signed credential. See
  [docs/action-passport-v2.md](action-passport-v2.md).
- **No production key management.** Dev-mode key generation writes raw
  private key bytes to a local file with best-effort file permissions.
  There's no HSM/KMS integration, no automated rotation workflow, and no
  revocation-and-reissue flow for a key discovered to be compromised.
- **The AgentEval bridge is a neutral, versioned export format, not a
  verified-compatible AgentEval schema implementation** — the exact
  upstream schema could not be confirmed when this was written. See
  [docs/agenteval-integration.md](agenteval-integration.md).
- **The CLI's `email` and `payment` reference adapters are in-memory
  only** — state does not persist across separate CLI process
  invocations (only the `sqlite` adapter does, via its own database file).
  `karmasakshi demo --all` is the way to see a full single-process
  walkthrough of all three.
- **Transactional outbox is single-node** (extreme-v2 Phase 15).
  `outbox.db` records commit intent; pending is not verified
  completion. See [docs/transactional-outbox.md](transactional-outbox.md).
- **Documented invariants are not a formal proof.** They are backed by
  unit, property (Hypothesis), adversarial, and bounded model-check
  tests — not by a theorem prover. Passing tests demonstrate the stated
  behavior under the scenarios exercised; they are not an exhaustive
  proof. See [docs/security-model.md](security-model.md).
- **The FastAPI control plane is process-local state.** `ApiState` is not
  designed for horizontal scaling as shipped; a real multi-instance
  deployment would need a shared grant store (Redis) and a shared audit
  backend, and the principal/manifest/grant in-memory caches in
  `ApiState` would need to move to shared storage too — that refactor is
  not implemented.
- **Windows file permission hardening is best-effort.** `chmod`-based key
  file protection (POSIX) has no equivalent hardening implemented for
  Windows ACLs in this codebase; the code catches the resulting `OSError`
  and continues rather than failing, which is a deliberate "don't block
  local dev on this" tradeoff, not a claim that the file is protected on
  Windows.

- **The Effect Intelligence Engine (`karmasakshi.intelligence`) is
  advisory only.** `assess()` scores a manifest and records the result in
  the audit journal; `authorize()`/`commit()` do not read or enforce its
  `recommendation`. See [docs/effect-intelligence.md](effect-intelligence.md)
  and the threat model's "New trusted component" section. (An
  `IntelligencePolicy` *can* now be cryptographically signed via a
  `PolicyBundle` -- see the next item -- but doing so still only pins
  *which* policy was used, not that its recommendation is enforced.)
- **Signed policy bundles and multi-party authorization
  (`karmasakshi.policy`, `karmasakshi.approval`) do not read
  `EffectAssessment` automatically.** A caller must explicitly configure
  `IntelligencePolicy`/`ApprovalPolicy` thresholds; there is no automatic
  link from a Phase 1 assessment's `required_human_approvals` to a Phase
  3 `ApprovalPolicy.required_approvals`. Approval roles are self-asserted
  (no RBAC/identity-directory check). The reference API signs every
  approval statement with one shared service key, not a distinct key per
  approver (the CLI does not have this limitation). See
  [docs/policy-bundles.md](policy-bundles.md) and
  [docs/multi-party-authorization.md](multi-party-authorization.md).
- **Separation-of-duty role facts beyond proposer/executor/approver are
  entirely caller-supplied** (`karmasakshi.duty.RoleAssignment`), with no
  cryptographic proof that a principal asserted as, say, `sealer`
  actually performed that action -- the same trust level already
  extended to `issuer`/`subject`/`proposer` elsewhere in this protocol.
  There is also no persisted field on `ExecutionGrant` recording that a
  separation check happened (unlike `policy_bundle_hash`/
  `approval_set_hash`); only the audit trail records it. See
  [docs/separation-of-duties.md](separation-of-duties.md).
- **Decision Envelope authorization still requires a concrete sealed
  manifest at authorize time** (`karmasakshi.envelope`). Deterministic
  substitution is implemented as library logic, but there is not yet a
  first-class lifecycle path that authorizes an open envelope and only
  later binds a concrete effect. Multi-node single-grant saga execution
  for graph-bound plans is deferred to a later phase. See
  [docs/decision-envelopes.md](decision-envelopes.md).
- **Independent witness quorum does not yet use sealed `witness.v1`
  policy bundles** (statements bind a plain `WitnessPolicy` hash).
  Durable multi-node witness collection stores are deferred to Phase 13+.
  Witness quorum is optional at PROVE time unless callers invoke
  `prove_with_witness_quorum`. See
  [docs/witness-quorum.md](witness-quorum.md).
- **Evidence quality evaluation is opt-in** (`karmasakshi.evidence`):
  adapters do not yet auto-emit `EvidenceRecord`s; callers must wrap
  `OutcomeProof` with an honest `EvidenceKind`. Sealed evidence-policy
  bundles are deferred. See [docs/evidence-quality.md](evidence-quality.md).
- **The public sandbox demo (`KARMASAKSHI_PUBLIC_DEMO=1`) is a single
  shared, in-memory session**, not multi-tenant: every visitor to a given
  deployment sees and can affect the same sandbox state until it
  auto-resets on a timer. It is a reference demo for exploring the
  protocol interactively, not a template for a multi-user production
  service. See [docs/deployment.md](deployment.md#public-sandbox-demo-mode).
- **Portable Evidence Pack offline verification proves internal
  consistency, not provenance** (`karmasakshi.portable`): a
  self-consistent, self-signed pack can be fabricated by anyone who
  controls key generation and still pass `verify_evidence_pack()`.
  Recipients who need to know the pack came from a specific organization
  must separately, independently confirm the embedded `key_id`s are
  trusted -- this pack alone does not establish that. A revoked key is
  also not re-checked against current trust status. See
  [docs/portable-evidence.md](portable-evidence.md).
- **Observability is advisory and not automatically wired into the
  lifecycle** (`karmasakshi.observability`): `engine.observe()` must be
  called explicitly by a caller (CLI/API) at the points that matter to
  it; nothing calls it automatically from `authorize()`/`commit()`. No
  remote/network sink ships in this phase -- only in-memory and local
  JSON-Lines file sinks. See [docs/observability.md](observability.md).
- **The AgentEval failure-memory store is advisory, unbounded, and
  exact-match only** (`karmasakshi.integrations.agenteval.memory`):
  nothing in `karmasakshi.engine` reads or writes it, it never expires
  entries, and two conceptually similar failures with a different
  `failure_category` string or cited `invariant` are treated as distinct
  shapes -- no fuzzy matching or clustering. Local file only, no
  shared/remote store. See
  [docs/agenteval-integration.md](agenteval-integration.md).
- **The Gateway's organization/user model (`karmasakshi.gateway`) is
  local development authentication only** -- PBKDF2 password hashing,
  no SSO, no MFA, and no server-enforced RBAC (`GatewayUserRole` is
  metadata, not currently checked by any authorization decision).
  Single-node SQLite only. Gateway sessions are process-local, in-memory,
  and non-durable -- a process restart invalidates every session; a
  horizontally scaled Gateway would need a shared session backend
  (Milestone B). No session revocation, password reset, or user-removal
  endpoint exists yet. See [docs/gateway.md](gateway.md).
- **The Gateway refund journey (`karmasakshi.gateway.refunds`) is
  payment-simulator-only and single-approver** -- no real payment
  provider; "agent"/"adapter registration" are not yet their own durable
  registries (an agent is just a `principal_id` string in the propose
  call); `approve`/`compensate` accept one authenticated session user's
  decision, not a configurable multi-approver quorum (Milestone B). No
  Control Center UI yet -- HTTP API only. See
  [docs/gateway.md](gateway.md).

## What "feature-complete" means here

Every capability listed in the original specification (protocol lifecycle,
manifest/grant primitives, delegation, TOCTOU protection, atomic
consumption, audit + passports, three reference adapters, LangGraph
integration, CLI, FastAPI control plane, AgentEval bridge) is implemented
with real logic and real tests — not stubbed, not mocked out, not marked
`@pytest.mark.skip`. "Feature-complete" describes breadth of implemented
functionality; it does not describe security certification, production
hardening, or scale-testing, none of which have been done.
