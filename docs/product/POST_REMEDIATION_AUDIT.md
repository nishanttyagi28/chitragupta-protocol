# Post-Remediation Release Audit (Milestone A) — Third Pass

**Audit date:** 2026-07-30  
**Audited branch:** `fix/ra002-and-policy-binding-gaps`  
**Audited commit:** `df9bad12f11db15ffa19333ebc8c075d9212ed6c`  
**Base of this branch:** `main` at `46919ce` (PR #48 original remediation) plus:

| Commit | Subject |
|---|---|
| `facdb3b` | Fix RA-002 refund-journey durability gap and policy-binding timing issue |
| `25effe7` | Fix signing-key durability gap found by the second independent audit |
| `df9bad1` | Fail closed on missing, corrupt, or mismatched durable signing keys |

**Prior document content:** the second-pass audit of `facdb3b` recommended
**NO-GO** for PRA-2026-1/2 (non-durable signing key). That prior verdict is
historical context only; this third pass is a fresh independent audit of
current HEAD after `25effe7` and `df9bad1`. The original baseline
`docs/product/RELEASE_AUDIT.md` remains unchanged (original NO-GO).

## Scope and method

Evidence-only. Fresh adversarial reproductions via standalone
`fastapi.testclient.TestClient` scripts against `create_app()` (not merely
re-running committed tests). Focused regression suite, full pytest +
coverage, ruff, mypy, bandit, pip-audit, build/twine, isolated wheel smoke,
and buyer-facing `karmasakshi-acceptance` were run from the current tree.

Docker Compose acceptance was not run locally (Docker unavailable in this
environment); that gate is required green via GitHub Actions.

## Executive verdict

**GO for Milestone A evaluation-ready self-hosted software**, conditional on
required CI (including compose-acceptance) being fully green on the merge
PR. No unresolved Critical or High blocker remains in the three release-
critical invariants below.

This is **not** a claim of production readiness, certification, formal
proof, or real-provider support.

## Invariant A — Durable refund rehydration

**Result: PASS** (fresh reproduction)

1. Bootstrap org, register agent/adapter, propose → approve to quorum →
   execute → verify.
2. Restart with a second `create_app(data_dir=...)` against the same
   directory.
3. After restart:
   - refund detail accessible (`200`, `commit_success=true`,
     `verification_status=verified_match`)
   - refund appears in Control Center list
   - Action Passport accessible; seal/grant/audit verification all `true`
   - audit evidence searchable for the manifest
   - idempotent re-execute returns `200`/`409` without manufacturing a
     replacement runtime or duplicating effect success incorrectly
   - signing key public material identical pre/post restart

## Invariant B — Proposal-time policy binding

**Result: PASS** (fresh reproduction, including across restart)

1. Activate policy A; propose and assess under A.
2. Activate policy B before approval.
3. Grant `policy_bundle_hash` equals policy A's hash, not B's.
4. Activate policy C; execute still succeeds bound to A's hash.
5. Across restart: propose under A2, switch to BX, restart, approve —
   grant still binds to A2's hash.

## Invariant C — Per-tenant signing-key durability

**Result: PASS** after `25effe7` + `df9bad1` (fresh reproduction)

| Check | Result |
|---|---|
| Tenant key restored on restart (not regenerated) | PASS |
| Pre-restart Passports verify after restart | PASS |
| Propose under activated policy after restart | PASS |
| Distinct tenants get distinct keys; no cross-tenant refund access | PASS |
| Clean first-start generates key + public sidecar | PASS |
| Corrupt private key fails closed (`KeyLoadError` at startup) | PASS |
| Missing private key with existing durable artifacts fails closed | PASS (`df9bad1`) |
| Mismatched private key vs `signing-key.pub` fails closed | PASS (`df9bad1`) |

**Third-pass High finding closed by `df9bad1`:** after `25effe7`, deleting
`signing-key.bin` for a tenant that already had durable signed records
still caused silent regeneration of a new Ed25519 identity. Prior grants/
policies then failed cryptographic verification and looked like tampering.
Fix: refuse startup when the private key is missing but the data directory
already holds protocol artifacts or a public-identity sidecar; also refuse
on corrupt key bytes and private/public mismatch. Clean empty first-start
still mints a key.

## Spot-check of prior remediations

Original RA-001 and RA-003–RA-011 remain present in `main` (PR #48). This
branch's diff is confined to durability/policy-binding/signing-key surfaces
and their tests plus documentation. No test assertions were weakened.

## Quality gates (this audit)

| Gate | Result |
|---|---|
| Full suite | `1049 passed, 8 skipped` |
| Coverage | `90.50%` |
| ruff check / format | Clean |
| mypy src | Clean (186 files) |
| bandit | No issues |
| pip-audit | No known vulnerabilities |
| build + twine | PASSED |
| Isolated wheel (Python 3.12) | Import + acceptance help OK |
| Buyer acceptance | **25/25 PASS** |
| Docker Compose acceptance | Not run locally; required CI job |

## Remaining honest limitations (not blockers for evaluation-ready)

- Payment-simulator in-memory balances still reset on process restart
  (Gateway records of what happened do not).
- Local evaluation auth is not production IAM / full RBAC.
- Compensation remains a single authorized HTTP call, not a separate
  multi-party quorum journey (RA-008 partial).
- No certification, formal proof, or real payment provider.
- Low findings RA-012–014 remain out of scope.
- Docker Compose acceptance must be confirmed green in CI on this PR.

## Release recommendation

**GO (evaluation-ready self-hosted software)** once required CI is fully
green. Merge only with no pending/failing required checks and no
unresolved Critical/High findings from this audit.
