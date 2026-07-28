# Changelog

All notable changes to this project are documented in this file. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
