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
  distributed audit backend shipped (only in-memory and SQLite).
- **Redis test coverage is environment-dependent.** The Redis backend's
  test suite is collected but every test skips (with an explicit reason)
  if no Redis instance is reachable. In the environment this branch was
  built in, that was the case — the Redis backend's logic is implemented
  and unit-testable in isolation, but was not exercised against a live
  Redis server as part of this build. Run `docker compose up redis` and
  re-run `pytest -m redis` to exercise it.
- **Multi-hop delegation revocation propagation is one-hop by default.**
  `engine.commit()` checks the immediate parent grant's revocation status
  automatically; a grandparent (or deeper) revocation requires calling
  `delegation.verify_delegation_chain()` explicitly with the full chain of
  grant objects. See [docs/delegation.md](delegation.md).
- **Compensation is best-effort, never guaranteed.** Some effects
  (irreversible ones by classification, or provider states that don't
  support cancellation, like a settled payment) honestly refuse
  compensation rather than pretending to roll back.
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
- **No rate limiting, DoS protection, or resource-exhaustion defense**
  anywhere in the CLI, API, or engine.
- **No formal verification.** The 38 documented invariants
  ([docs/security-model.md](security-model.md)) are backed by unit tests,
  property-based tests (Hypothesis), and adversarial-input tests — not by
  a theorem prover or model checker. Passing tests demonstrate the stated
  behavior under the scenarios exercised; they are not an exhaustive
  proof.
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
- **The public sandbox demo (`KARMASAKSHI_PUBLIC_DEMO=1`) is a single
  shared, in-memory session**, not multi-tenant: every visitor to a given
  deployment sees and can affect the same sandbox state until it
  auto-resets on a timer. It is a reference demo for exploring the
  protocol interactively, not a template for a multi-user production
  service. See [docs/deployment.md](deployment.md#public-sandbox-demo-mode).

## What "feature-complete" means here

Every capability listed in the original specification (protocol lifecycle,
manifest/grant primitives, delegation, TOCTOU protection, atomic
consumption, audit + passports, three reference adapters, LangGraph
integration, CLI, FastAPI control plane, AgentEval bridge) is implemented
with real logic and real tests — not stubbed, not mocked out, not marked
`@pytest.mark.skip`. "Feature-complete" describes breadth of implemented
functionality; it does not describe security certification, production
hardening, or scale-testing, none of which have been done.
