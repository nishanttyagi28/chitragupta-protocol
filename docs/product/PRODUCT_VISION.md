# KarmaSakshi Product Vision

**KarmaSakshi Protocol** — *Seal the intended effect. Witness the actual outcome.*

## Positioning

Runtime trust infrastructure for consequential AI-agent actions.

KarmaSakshi is **not**:

- IAM / OAuth / SSO (identity)
- a policy gateway alone (allow/deny without sealed effect identity)
- a workflow engine
- agent observability / tracing
- offline evaluation / offline benchmarks as the primary product

It answers a different question: **was this exact intended effect authorized, executed at most once as authorized, and independently observed?**

## Core lifecycle

```text
PROPOSE → PREPARE → ASSESS → SEAL → AUTHORIZE → COMMIT → VERIFY → PROVE
```

## Product surfaces

| Surface | Role |
|---|---|
| **KarmaSakshi Core** | Protocol library, adapters, passports, audit |
| **KarmaSakshi Gateway** | HTTP API for effect lifecycle and approvals |
| **KarmaSakshi Control Center** | Human approval inbox, timeline, passport viewer |
| **KarmaSakshi Enterprise Layer** | Signers, SSO interfaces, multi-witness, retention |

## First commercial use case

**AI-operated customer refund** — an agent proposes an exact refund effect; policy and humans authorize; the payment simulator (or real adapter) commits; independent ledger observation produces a signed Action Passport.

## Honesty

Pricing, certifications, customer counts, and production readiness claims are **not** asserted here. See `PRICING_PROPOSAL.md`, `SECURITY_FAQ.md`, and `docs/limitations.md`.
