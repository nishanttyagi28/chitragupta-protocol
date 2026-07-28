# Threat Model

**This document describes what KarmaSakshi Protocol is designed to
resist and, equally importantly, what it is not. It is not a security
certification.**

## In scope: what the protocol defends against

1. **A compromised or misaligned agent proposing a different effect than
   what a human approved.** Defended by binding authorization to a
   canonical hash of the exact resolved effect (`EffectManifest`), not to
   a tool name or free-text description. Any field change invalidates the
   seal (invariant #3).
2. **A resolved effect whose target/amount changes between preparation and
   execution (TOCTOU).** Defended by `StateFingerprint` preconditions
   re-checked immediately before commit (invariant #14).
3. **An agent issuing its own authorization.** Structurally impossible —
   `issue_grant()` rejects an agent-typed issuer outright (invariant #30).
4. **A grant being replayed, reused beyond its intended count, or used
   concurrently by racing callers.** Defended by atomic
   reserve/commit/release semantics in the grant store (invariants #4, #5).
5. **A sub-agent or delegated grant exceeding the authority it was
   delegated.** Defended by attenuation checks on every dimension
   (invariants #15-#18).
6. **Trusting a tool's "success" response as proof the real-world effect
   matched intent.** Defended by a separate, independent verification step
   that re-observes external state (invariants #20, #21) — demonstrated
   concretely by the payment simulator's ambiguous-timeout mode.
7. **Silent tampering with the audit trail after the fact.** Defended by a
   hash-chained, append-only journal (invariant #22).
8. **A forged signature on an otherwise-unchanged manifest or grant.**
   Defended by full cryptographic verification (hash *and* signature) at
   every consumption point, including `commit()`, not just `authorize()`.
9. **Storage or audit-sink outages producing an indeterminate "maybe it
   worked" state.** Defended by fail-closed error propagation — no
   `except: pass` anywhere in the commit path (invariants #10, #23).

## New trusted component: the Effect Intelligence Engine

`karmasakshi.intelligence` (see [docs/effect-intelligence.md](effect-intelligence.md))
adds a deterministic risk-scoring engine over `EffectManifest` +
`IntelligencePolicy` + `AssessmentFacts`. It contains no LLM and makes no
security decision by itself -- it is pure, versioned arithmetic, and its
output (`EffectAssessment`) is recorded in the same hash-chained audit
journal as every other engine step.

**It does not currently change the security model.** `authorize()` and
`commit()` do not read `EffectAssessment.recommendation`; a `BLOCK`
recommendation is informational only in this protocol version. Do not
treat calling `assess()` (or seeing `recommendation: block` in a passport)
as evidence that a manifest was actually blocked -- check the lifecycle
state and the presence/absence of a valid `ExecutionGrant` instead. Wiring
a `BLOCK` recommendation (or an unmet approval/witness-quorum requirement)
into a structural authorization gate is planned for a later phase (signed
policy bundles binding `policy_hash` into the grant, plus M-of-N
authorization) and is **not implemented today**.

`IntelligencePolicy` itself is an unsigned, in-process value: whoever
constructs the `EffectIntelligenceEngine` a caller uses controls the
thresholds, with no cryptographic binding yet to prevent a compromised
caller from picking permissive thresholds and calling the result
authoritative advice.

## Explicitly out of scope

- **Compromise of the machine running the engine.** If an attacker has
  arbitrary code execution on the host, they can read private key material
  from wherever it's loaded (file, env var) — this protocol does not
  implement HSM/KMS integration, secure enclaves, or memory protection
  against a co-resident attacker. Production deployments should load keys
  from a proper secret manager and consider hardware-backed signing;
  neither is implemented here.
- **A malicious or compromised adapter.** The engine trusts that an
  adapter's `prepare()` accurately resolves the request and that
  `validate_preconditions()`/`verify()` accurately reflect external state.
  A deliberately dishonest adapter (e.g. one that always reports
  `matched_expected=True` regardless of reality) defeats verification.
  Adapters are part of the trusted computing base — write and review them
  accordingly (see [docs/adapter-authoring.md](adapter-authoring.md)).
- **Denial of service.** Nothing here rate-limits proposal volume,
  protects the audit journal from unbounded growth, or defends the API/CLI
  process against resource exhaustion.
- **Side-channel attacks on the signing operation** (timing attacks on
  Ed25519 verification, etc.) — the `cryptography` library's implementation
  is trusted as-is; no additional hardening is applied.
- **Multi-machine distributed consensus beyond what Redis's atomicity
  provides.** The Redis backend gives atomic single-key check-and-set
  across processes/machines sharing one Redis instance; it does not
  implement Raft/Paxos-style consensus, leader election, or partition
  tolerance beyond what Redis itself offers.
- **Formal verification.** The 30 invariants in
  [docs/security-model.md](security-model.md) are tested (unit,
  property-based, adversarial), not proven with a theorem prover or model
  checker.
- **Recovering from a compromised signing key.** Key rotation is
  supported (`Keyring.add_key`/`.remove_key`), but there is no automated
  revocation-and-reissue workflow for grants signed by a key discovered to
  be compromised after the fact.
- **Enforcement of Effect Intelligence Engine recommendations.** See "New
  trusted component" above -- `assess()` scores and records, it does not
  gate.

## Trust boundaries (see also docs/architecture.md)

```text
[Agent / LLM]  --produces-->  [raw request]
     |  no signing key, no grant-issuance capability, ever
     v
[Adapter.prepare()]  --produces-->  [EffectManifest]
     v
[Engine.seal()]  (holds the signing key)  --produces-->  [SealedManifest]
     v
[Human or Service principal]  --calls engine.authorize()-->  [ExecutionGrant]
     v
[Engine.commit()]  (the only place that decides whether to call the adapter)
     v
[Adapter.commit()]  --performs-->  [External system]
```

The signing key lives only inside the process holding `EngineContext`/the
CLI workspace/the API's `ApiState` — it is never serialized into a
manifest, grant, audit event, passport, or anything handed back to an
agent (see the LangGraph integration's
`test_interrupt_payload_never_contains_signing_material`).

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
