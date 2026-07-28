# Comparison

This document compares **architectural responsibility and capability
category**, not implementation quality, maturity, or benchmark results.
Every claim about another project below is drawn directly from that
project's own public documentation, reviewed on 2026-07-28, with a source
link. Where a dimension is not addressed in the documentation reviewed,
this file says so explicitly (**"not stated in the reviewed
documentation"**) rather than assuming absence. None of these projects'
implementations were run, audited, or tested — only their own published
claims were read.

## Category distinction: evaluation vs. runtime authorization

```text
AgentEval:
  Did the agent behave correctly during development and CI?

Chitragupta Protocol:
  Did the exact approved real-world effect match the actual outcome?
```

AgentEval-style tooling evaluates agent behavior against test cases,
typically offline or in CI, before or after the fact. Chitragupta Protocol
operates at runtime, on individual consequential actions: it stages an
exact effect, seals it, requires a non-agent principal to authorize that
exact sealed effect, executes it, and independently verifies the outcome.
These are complementary rather than competing — a production failure
caught by Chitragupta Protocol's verification step can be exported
(`chitragupta.integrations.agenteval`) as a regression fixture for
AgentEval-style offline evaluation to catch going forward. See
[docs/agenteval-integration.md](agenteval-integration.md) for the honest
caveat that the exact AgentEval fixture schema was not confirmed, so this
export is a neutral, versioned format rather than a claimed-compatible one.

## Not another agent permission layer

Most of the products below (and most agent frameworks' built-in
permissioning) answer one of three different questions. Chitragupta
Protocol answers a fourth, distinct question:

- **IAM** answers: *who is this agent, and what identity does it hold?*
- **OAuth-style delegation / credential brokers** answer: *which
  service credentials, and under what scope, may this agent use?*
- **Policy gates / agent gateways** answer: *is this tool call allowed
  right now, against current policy?*
- **Chitragupta Protocol** answers: *did the exact real-world effect a
  human approved become the exact real-world outcome that actually
  happened — provably?*

These questions are not mutually exclusive, and a real deployment likely
needs answers to all four. Chitragupta Protocol does not attempt to be an
identity provider, a credential vault, or a general-purpose policy engine
— it assumes something upstream has already decided the agent may attempt
an action, and picks up from there: resolving that attempt into one exact,
cryptographically sealed effect; revalidating the world hasn't changed
underneath it; executing with exactly-once semantics; and independently
proving what actually happened. See
[Not another agent permission layer](../README.md#not-another-agent-permission-layer)
in the README for the same distinction with worked examples.

## Capability-boundary comparison

Reviewed 2026-07-28. Official documentation sources:

- **Grantex** — [docs.grantex.dev/introduction](https://docs.grantex.dev/introduction), [grantex.dev](https://grantex.dev/)
- **AgentLattice** — [agentlattice.io](https://www.agentlattice.io/)
- **Xybern** — [xybern.com/authorisation-layer](https://xybern.com/authorisation-layer)
- **OpenLeash** — [openleash.ai](https://openleash.ai/), [openleash.ai/concepts/ai-agent-authorization](https://openleash.ai/concepts/ai-agent-authorization/)
- **Meandr** — no official public documentation was located for a product
  or project named "Meandr" in the AI-agent authorization /
  credential-broker / policy-gateway space at the time of this review.
  It is listed for completeness because it was requested; every cell for
  it below is **"no public documentation found"**, not a claim about
  what it does or doesn't do.

| Dimension | Grantex | AgentLattice | Xybern | OpenLeash | Meandr | Chitragupta Protocol |
|---|---|---|---|---|---|---|
| **Primary responsibility** | Delegated authorization / identity for agents ("OAuth for agents") | IAM for AI agents (identity + policy gate + audit) | Enterprise agent-action enforcement layer ("Charter"-based interception) | Local-first authorization sidecar for risky agent actions | no public documentation found | Verified effect commit protocol: seal one exact effect, prove its real outcome |
| **Tool/scope authorization** | Yes — scoped, time-limited, revocable delegation tokens (DIDs + JWT) | Yes — policy-as-code `gate()` calls, fail-closed, narrowing-only scope | Yes — every agent action intercepted and evaluated against a "Charter" | Yes — `POST /v1/authorize`, YAML policies, ALLOW/DENY/escalate | no public documentation found | Yes — `ExecutionGrant` (scoped, expiring, revocable, single-use-by-default); a **supporting control**, not the primary claim (see below) |
| **Exact resolved-effect sealing** (target, amount, parameters bound into one signed, hashed object) | Not stated in the reviewed documentation | Not stated in the reviewed documentation | Not stated in the reviewed documentation | Partial — authorization considers action type, target, cost, and counterparty; not stated whether these are bound into one canonical, cryptographically hashed object | no public documentation found | **Yes** — `EffectManifest.canonical_hash()`; the grant is bound to this exact hash, not a tool name |
| **External-state preconditions captured at authorization time** | Not stated | Not stated | Not stated | Not stated | no public documentation found | **Yes** — `StateFingerprint` / `Precondition` on the manifest |
| **Commit-time TOCTOU revalidation** (preconditions re-checked immediately before the effect, not only at approval time) | Not stated | Not stated | Not stated | Not stated | no public documentation found | **Yes** — `adapter.validate_preconditions()` re-invoked inside `engine.commit()`; fails closed with `StaleManifestError` |
| **Exactly-once effect reservation** (atomic reserve before execution, consume only on success) | Not stated | Not stated | Not stated | Not stated | no public documentation found | **Yes** — atomic reserve/release/commit across memory, SQLite, and Redis backends |
| **Ambiguous-outcome crash recovery** (explicit recovery path for a crash between the external effect succeeding and the local record finalizing, without blind retry) | Not stated | Not stated | Not stated | Not stated | no public documentation found | **Yes** — `engine.recover_ambiguous_commit()`; documented in [docs/crash-recovery.md](crash-recovery.md) |
| **Independent post-execution state verification** (re-observing the real external system, not trusting the call's return value) | Not stated | Not stated | Not stated | Not stated (proof token verifies the authorization decision, not the executed outcome) | no public documentation found | **Yes** — `adapter.verify()` re-queries the adapter's own external system of record |
| **Intent-vs-outcome mismatch proof** (detecting and recording when a provider reports success but real state differs) | Not stated | Not stated | Not stated | Not stated | no public documentation found | **Yes** — `OutcomeProof.matched_expected`; demonstrated live in the [public sandbox](../README.md#try-it-live) and `chitragupta demo --all` scenario 12 |
| **Action Passport equivalent** (a document proving the full proposed → approved → committed → verified chain for one specific effect) | Partial — "Grantex passports" are W3C Verifiable Credentials proving the *delegation/identity chain*; not stated to prove an executed outcome | Partial — hash-chained, independently-verifiable *decision* audit trail; not stated to include outcome verification | Partial — "Provenance Vault" signed record per *decision*; not stated to include independent outcome verification | Partial — signed proof token (PASETO v4.public) proving the *authorization decision* was made; not stated to include independent outcome verification | no public documentation found | **Yes** — `ActionPassport` independently re-verifies seal, grant, and audit chain at generation time and includes the verified-outcome section; see [docs/action-passports.md](action-passports.md) |

**How to read the "partial" cells honestly:** four of these five products
document a proof or passport artifact — but in every case reviewed, it is
a signed record of *the authorization decision* (who was allowed to do
what, and when), not an independently re-verified record of *what the
external system actually ended up in*. That distinction — proof of a
decision versus proof of a real-world outcome — is the specific gap
Chitragupta Protocol's Action Passport and `VERIFY` step target. This is a
description of documented scope, not a claim that the other products are
deficient at what they set out to do.

## Comparison to generic tool-permission layers

Many agent frameworks implement authorization as "may this agent call
this named tool" (optionally with a JSON-schema-validated argument shape).
That is a real and useful control, but it authorizes the *capability*, not
the *exact resolved effect*. Chitragupta Protocol's manifest/grant binding
is a stricter, narrower claim: a grant is valid for one specific,
canonically-hashed effect (target, amount, parameters, preconditions),
not for "any call matching this tool's schema." The two approaches are not
mutually exclusive — a tool-permission layer can sit in front of
Chitragupta Protocol's `prepare()` step to decide which tools an agent may
even attempt to resolve into a manifest.

## Questions worth asking when evaluating any of these against each other

1. Does authorization bind to the exact resolved effect (target, amount,
   parameters, preconditions), or to a tool name / capability?
2. Is there independent, post-execution verification of the actual
   outcome, or does the system trust the tool call's return value?
3. Is there TOCTOU protection — does authorization survive external state
   changing between approval and execution, or does it silently execute
   against whatever state exists at call time?
4. Is exactly-once execution guaranteed under concurrent retries, with an
   explicit (non-blind-retry) recovery path for ambiguous crashes?
5. Does the audit/proof artifact cover the executed outcome, or only the
   authorization decision?

Chitragupta Protocol's answers to all five are implemented and tested —
see [docs/security-model.md](security-model.md) for exactly where.
