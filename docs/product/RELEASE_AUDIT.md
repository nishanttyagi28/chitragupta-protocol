# Milestone A Release Audit

**Audit date:** 2026-07-30  
**Audited branch:** `main`  
**Audited commit:** `cea249647dea66cb4adca2f9bd9f62f53b9c9801`  
**Commit subject:** `Complete Milestone A evaluation product (#47)`  
**Recommendation:** **NO-GO**

## Scope and method

This was an evidence-only audit. Product code, tests, configuration, existing
documentation, and media were not changed. The only repository change made by
the audit is this report.

Claims in `README.md`, `docs/product/BUILD_STATUS.md`, and
`docs/product/MVP_ACCEPTANCE.md` were treated as assertions to test, not as
evidence. Evidence came from:

- direct source and test inspection;
- fresh local tests and adversarial reproductions on the audited commit;
- a fresh isolated package build and wheel installation;
- fresh generation of the Control Center screenshots, GIF, and MP4 from a
  running local Gateway;
- Git and GitHub state queried independently;
- GitHub Actions metadata for the exact PR head whose tree was merged; and
- Docker configuration/source inspection where local execution was impossible.

No remediation was applied.

## Executive verdict

The repository contains a real protocol implementation, real Gateway routes,
typed sync/async clients, and a real server-rendered Control Center. The UI uses
the Gateway through `AsyncGatewayClient` and an ASGI transport; it does not
hardcode successful refund states. The complete local suite passes, coverage is
above the configured gate, static analysis passes, the package builds, and PR
#47's CI and Security workflows were green.

Those facts are not sufficient for release. Four independently reproduced
failures invalidate the statement that Milestone A is complete:

1. **Critical:** an unvalidated organization ID controls a filesystem path and
   permits protocol databases to be created outside the configured tenant root.
2. **High:** a process restart preserves organization credentials but loses the
   tenant runtime, making authenticated refund routes return HTTP 500.
3. **High:** an activated organization risk policy is not used to assess a
   refund. The UI can display `BLOCK` while still offering approval and
   permitting commit.
4. **High:** successful recovery of a real settle-then-timeout outcome leaves
   lifecycle state `failed`; the refund read model says `verified_match` while
   Action Passport V2 says `failed`.

There is also no authorization model that makes a “3-person” quorum meaningful:
any authenticated organization user can create additional accounts, and those
accounts can satisfy the quorum. This is disclosed as “no server-enforced RBAC”
in limitations, but conflicts with buyer-facing “human” and “three-person”
wording.

## Repository and GitHub state

| Check | Exact result | Verdict |
|---|---|---|
| Current branch | `main` | Verified |
| Initial worktree | `## main...origin/main`, no changed/untracked files | Verified clean before audit |
| Local HEAD | `cea249647dea66cb4adca2f9bd9f62f53b9c9801` | Verified |
| `origin/main` | `cea249647dea66cb4adca2f9bd9f62f53b9c9801` | Verified equal to local HEAD |
| Latest history | `cea2496` #47, `7ec7b24` #46, `c55e84c` #45, `c0adfec` #43, `270e303` #42, `a5f597e` #41 | Verified |
| Open PRs | GitHub query returned none | Verified |
| PR #47 | Merged; head `7697ddb569d61f11ea09c0e24f751815bd474a17` | Verified |
| PR-to-main content | PR-head tree and merge-commit tree have no diff | Verified |
| Recent merged slices | #41, #42, #43, #45, #46, #47 | Verified |
| Review | Only automated GitHub Advanced Security comment; no human approval | Limitation, not a failed repository claim |
| Audit worktree | This report is intentionally the only new repository file | Expected |

PR #47's exact head had successful GitHub Actions runs:

- CI run `30482174451`: Compose buyer acceptance, package build, Python
  3.10/3.11/3.12/3.13 tests, Ruff, mypy, documentation checks, coverage, and
  wheel smoke all succeeded.
- Security run `30482174497`: Bandit, `pip-audit`, and CodeQL all succeeded.
- The Compose run published `milestone-a-acceptance`, artifact ID
  `8736111076`, digest
  `sha256:18f82937784b5b6bcf0fd063ac607063825965feee8ff14e8ec147718f684b9b`,
  against that exact PR head.

This historical CI evidence does not override newly disclosed vulnerabilities
or the local adversarial reproductions below. In particular, a fresh dependency
audit now fails on a newly known pytest advisory.

## Claim audit: `README.md`

The README contains many explanatory statements. The table maps every
release-relevant factual claim family to implementation and tests; descriptive
problem statements and links are not repeated as separate claims.

| README claim | Evidence | Result |
|---|---|---|
| Exact effect is canonicalized, sealed, grant-bound, commit-time preconditions are rechecked, execution is atomically reserved/idempotent, outcome is independently observed, and evidence is generated | `domain/`, `canonical/`, `engine/core.py`, grant stores, adapter `verify()` methods, Passport/evidence modules; full unit/property/adversarial suite and fresh 15/15 demo | **Verified for the reference implementation** |
| “Milestone A local evaluation product complete” | Real vertical slice exists, but RA-001 through RA-005 are release blockers | **Failed** |
| Gateway, typed sync/async SDK, authenticated Control Center, inventory, assessment-derived quorum, Compose, and 25-check command ship | Source, wheel contents, focused tests, fresh acceptance/media runs, and exact-head CI | **Verified with findings below** |
| Not certified, independently audited, production proven, or a real payment integration | Source and docs show simulators/local auth; no contrary evidence | **Verified limitation** |
| All 25 extreme-v2 phases implemented | Corresponding modules/docs/tests exist and full suite passes; this audit did not constitute formal verification of all 74 security invariants | **Verified structurally/test-wise, not formally proven** |
| GIF/video show a real authenticated Control Center and are reproducible | Capture scripts start real uvicorn, run acceptance, seed via SDK, and use Chromium. Fresh reproduction generated equivalent pages and matching dimensions. | **Verified behavior; historical file provenance has no signed attestation** |
| Server-enforced “three-person” approval quorum | Server enforces distinct authenticated user IDs, but any member can create more users and roles are not authorized | **Misleading / failed human-person interpretation** |
| Docker command prints 25 passes and stores report in named volume | Exact-tree CI Compose job passed and published a 25-check report | **Verified in CI; local Docker unverified** |
| “Simulator data lives in a named volume” | Files are under `/data`, but simulator ledger, manifests, proofs, grants maps, active policy, and signing key are process-local and are not rehydrated | **Misleading / failed persistence interpretation** |
| Control Center overview, approval inbox, exact effect, risk/policy, Passport, and searchable audit are real | Routes fetch Gateway data via typed async SDK; fresh screenshots reproduce these pages | **Verified** |
| A successful reference refund can be committed once and independently confirmed | Fresh tests/demo and acceptance; engine and adapter inspection | **Verified** |
| If target, amount, state, manifest, authorization, or preconditions change, execution fails closed | Core validation plus adversarial tests; acceptance exercises original grant against changed effect | **Verified for exercised adapters** |
| Agent cannot issue its own grant; human/service principal is required | Core invariant and adversarial tests | **Verified at protocol-principal level** |
| Effect Intelligence policy decision controls approval/commit | README calls the engine advisory elsewhere, but UI presents a policy decision and permits a `BLOCK` recommendation to proceed | **Not claimed as enforcement in limitations; buyer UX is misleading** |
| 15-scenario deterministic demo output is real | Fresh `karmasakshi demo --all`: `15/15 scenarios behaved as expected` | **Verified** |
| Three reference adapters exist; SQLite persists while email/payment CLI adapters are in-memory | Source and tests | **Verified** |
| Action Passport independently re-verifies seal, grant, and audit | Passport generators and tests | **Verified** |
| “signed Action Passport” | V2 has a deterministic content hash but is explicitly “not a separately signed credential” in `docs/action-passport-v2.md:72-74` | **Failed wording** |
| API deployment modes and public-demo/dev-mode conflict protection exist | `api/auth.py`, `api/app.py`, deployment tests | **Verified** |
| Docker health check exists | Dockerfile and Compose both probe `/health` | **Verified, but it is liveness only** |
| Test count “768 passed, 8 skipped, 90.37%” is from a real run on this branch | Block labels it Phase 24, but it is stale for current main; fresh current result is 910/8 and 90.42% | **Misleading/stale** |
| CI runs tests on Python 3.10–3.13, Ruff, mypy, Bandit, CodeQL, and dependency audit | Workflow definitions and exact-head successful jobs. The dependency job does not install/audit the development dependency group. | **Verified historically, incomplete dependency scope** |
| Stated production limitations (single-node SQLite, simulators, best-effort compensation, no audit/certification) | Source agrees | **Verified** |

## Claim audit: `docs/product/BUILD_STATUS.md`

| Status row | Independent result |
|---|---|
| Product vision/architecture drafted | **Verified.** Files exist and match the code at a high level. |
| MVP checklist passing with 25 checks | **Mechanically verified, substantively partial.** Fresh acceptance passed 25 checks, but several labels overstate what they prove and omit the blockers in this report. |
| Durable organization/user and inventory model with migrations | **Verified for those four Gateway tables.** Refund runtime is not durable/rehydrated. |
| Bootstrap/login/user API, sessions, cross-org failure | **Verified with security exceptions:** empty passwords are accepted, any member may create users, bootstrap is not atomic, and `org_id` enables path escape. |
| Refund vertical slice including policy, recovery, compensation, isolated engine | **Implementation exists; completion claim failed.** Active policy is disconnected from assessment, recovery state is contradictory, restart loses runtime, and compensation is auto-authorized in one request. |
| Control Center UI journey, isolation, CSRF, cookies/logout/errors | **Verified.** Real SDK/Gateway calls and security controls exist. Server authorization lacks RBAC, and the UI renders the policy/recovery contradictions returned by the server. |
| Typed sync/async SDK covers Gateway surface | **Verified.** Focused SDK tests pass and wheel includes clients/models. |
| Compose evaluation product with volume, health-gated acceptance, CI | **Verified as configuration and exact-tree CI execution.** The implied runtime persistence and readiness are inadequate. |
| Authenticated real-browser media | **Verified by fresh reproduction and visual inspection.** No signed provenance attestation for the checked-in bytes. |
| Automated acceptance passing locally and in Compose CI | **Verified mechanically:** 25/25 locally and exact-tree Compose CI green. Test strength findings remain. |
| Milestone B/C not started | **Verified in product status.** This audit did not start them. |
| “Milestone A implementation is complete” | **Failed.** NO-GO blockers remain. |

## Claim audit: `docs/product/MVP_ACCEPTANCE.md`

| Checklist item | Implementation/test evidence | Audit result |
|---|---|---|
| Organization created | Gateway migration/store/bootstrap; acceptance check 1 | **Pass, with RA-001 and non-atomicity** |
| Authenticated team member | PBKDF2 store auth and session; checks 2, 8, 9 | **Pass for local evaluation, with empty-password/RBAC limitations** |
| Refund agent registered | Durable org-scoped inventory; check 3 | **Pass** |
| Payment simulator registered | Durable adapter declaration and runtime version/effect validation; check 4 | **Pass** |
| Signed organization policy activated | Signed bundle stored and later hash-bound; check 5 | **Partial: activation is real, assessment ignores it** |
| Exact refund effect proposed | Prepare/seal and exact before/after parameters; check 6 | **Pass** |
| Risk assessment displayed | Structured engine result and UI; checks 7/11 | **Pass, but uses engine default rather than active org policy** |
| Human approval requested | Sealed item in real approval inbox; check 10 | **Pass as UI state** |
| Required quorum completed | Distinct user IDs and approval policy; checks 12/13 | **Partial: accounts, not independently authorized humans** |
| Effect committed exactly once | Grant reservation/idempotency and simulator; checks 15/16 | **Pass for exercised process** |
| Independent ledger observation | Adapter re-observation; check 17 | **Pass** |
| Signed Action Passport generated | Passport V2 hash and embedded signed anchors; check 18 | **Fail wording: Passport itself is not signed** |
| Audit trail searchable | Org-scoped query and chain check; checks 19/25 | **Pass** |
| Modified amount/recipient rejected | Core grant/manifest binding and changed-effect acceptance scenario | **Pass; acceptance label is broader than its single scenario** |
| Duplicate retry prevented | Second execute returns 409; core concurrency/idempotency tests | **Pass** |
| Ambiguous timeout recovered honestly | Real settle-then-timeout is observed and matched | **Fail as complete lifecycle: read model and Passport contradict** |
| Compensation as separate authorized effect | Separate manifest/grant created | **Partial: same caller auto-authorizes and commits in one request without refund quorum** |
| Cross-tenant access rejected | Common resolver, focused tests, acceptance second org | **Pass for exercised routes; test name overstates endpoint coverage** |
| Offline Passport/audit verification | Evidence Pack verification; check 23 | **Pass for internal consistency, not third-party provenance** |

The checked-in report has exactly 25 passing entries. Its labels are not a
one-to-one match with the 19-item checklist: UI login/session and audit-chain
checks are additional, while some checklist assertions combine several
properties.

## Complete refund journey trace

| Stage | Real implementation | Tests/evidence | Result |
|---|---|---|---|
| Organization bootstrap | `POST /gateway/organizations`, SQLite org/owner, tenant provisioning | Gateway integration and fresh probes | **Exists; unsafe ID and non-atomic** |
| Authentication | PBKDF2 password hashing, random salt, constant-time comparison, random 12-hour bearer sessions | Gateway/UI tests | **Exists; local-only, empty password accepted** |
| Policy activation | Per-org signed `IntelligencePolicy` bundle | Refund tests/acceptance | **Exists; not applied to assessment** |
| Proposal | Registered agent and exact payment adapter required; engine prepare | Refund/SDK/acceptance tests | **Pass** |
| Assessment | Deterministic Effect Intelligence engine | Unit/adversarial/refund tests | **Pass in isolation; wrong policy in Gateway** |
| Sealing | Canonical manifest hash + Ed25519 seal | Core/adversarial tests | **Pass** |
| Human approval | Session-derived approver ID, signed statement, distinct-ID quorum | Refund/UI/approval tests | **Mechanically pass; human authorization gap** |
| Commit | Exact seal/grant/policy verification, precondition recheck, atomic reserve, adapter commit | Core/property/adversarial/refund tests | **Pass for exercised state** |
| Independent verification | Adapter re-observes simulator ledger | Refund/acceptance tests | **Pass** |
| Action Passport | V1/V2 generators recheck seal/grant/audit; V2 hash | Passport/evidence tests | **Pass except “signed Passport” wording and ambiguity state** |
| Evidence export | Self-contained Evidence Pack and offline verifier | Portable evidence tests/check 23 | **Pass for consistency; provenance caveat documented** |
| Audit trail | SQLite hash-chained journal, org-scoped search and verify | Audit tests/UI/checks 19/25 | **Pass single-node** |
| Ambiguous recovery | No blind retry; adapter re-observation records idempotent outcome | Crash recovery tests and fresh settle-timeout probe | **Recovery evidence works; lifecycle/Passport fail** |
| Compensation | Separate compensation manifest and grant, honest refusal for settled payment | Compensation tests/check 22 | **Structurally separate; authorization workflow is weak** |

## Control Center audit

### Verified real-data path

`src/karmasakshi/web/control_center.py` constructs
`AsyncGatewayClient(..., transport=httpx.ASGITransport(app=request.app))`.
Every dashboard, approval, detail, Passport, and audit route obtains the
organization ID from the authenticated session and invokes the Gateway client.
Approve, deny, execute, verify, and recover are POST actions that invoke
server routes. No template contains a hardcoded successful refund outcome.

The UI implements:

- organization overview and counts;
- a real pending approval inbox;
- exact source balance before/expected after and beneficiary credit;
- risk score, structured signals, recommendation, and approval requirements;
- server-issued approval/denial/grant actions;
- audit-backed lifecycle timeline;
- commit, verification, ambiguity, and recovery states;
- Action Passport V2;
- searchable organization audit; and
- safe error pages without raw internal exceptions.

### Session and browser controls

Verified in source and focused integration tests:

- `HttpOnly`, `SameSite=Strict` session cookie;
- `Secure` cookie flag when the observed request scheme is HTTPS;
- random server-side bearer session and fixed expiry (no silent renewal);
- HMAC-derived per-session CSRF for authenticated mutations;
- double-submit random CSRF cookie for login;
- logout revokes server session and clears browser cookie;
- `Cache-Control: no-store`;
- CSP denying scripts, frames, foreign connections, and foreign form actions;
- `Referrer-Policy: no-referrer`, `nosniff`, and frame denial;
- generic login failure and bounded safe API error messages; and
- server-derived organization scope.

These controls do not supply RBAC, MFA, SSO, durable sessions, password policy,
or trusted human identity; those are separate findings/limitations.

## Security and adversarial results

| Property requested | Evidence/result |
|---|---|
| Tenant isolation | Common org resolver and exercised 403 cross-tenant scenarios pass. Critical filesystem tenant-root escape is a different isolation failure. |
| Authentication | Invalid/missing sessions fail closed; suspended org invalidates a live session. Empty password is accepted at creation and login. |
| Authorization | Manifest grant checks pass. Gateway has no role authorization; any authenticated member can create users and those users can approve. |
| CSRF | Missing/invalid login and authenticated-action CSRF rejected in focused UI tests. |
| Session security | Random expiring tokens, HttpOnly/SameSite cookies, conditional Secure, logout revocation verified. Process restart invalidates sessions by design. |
| Modified manifest | Signature/grant binding rejects amount/recipient changes in core/adversarial tests and acceptance. |
| Duplicate prevention | Atomic reservation, single-use grant, and idempotency tests pass; buyer retry receives 409. |
| Ambiguous outcome | Blind retry is avoided and external evidence is found, but terminal state remains contradictory (RA-004). |
| Audit tamper | Hash-chain tampering and modified evidence are rejected in unit/adversarial tests and demo. |
| Rate/resource limits | Process-local middleware exists; it is not a WAF and was not load-tested. |

## Docker, migrations, health, and startup

Local Docker execution was not possible: `Get-Command docker` returned
`DOCKER_NOT_FOUND`. This is an explicit audit limitation, not a pass.

The exact PR-head tree that was merged did pass GitHub's Docker Compose buyer
acceptance job. Static inspection confirms:

- API is bound to `127.0.0.1:8000`;
- evaluation mode explicitly enables unauthenticated platform bootstrap;
- `/data` is a named volume;
- acceptance waits for API health and writes its JSON report under `/data`;
- image runs as non-root UID 1000;
- Docker installs the API extra, so the container includes `httpx`; and
- CI tears down its volumes after exporting the report.

Operational failures:

- `/health` always returns `{"status":"ok"}` and is only liveness.
- `/ready` verifies only the core audit journal. It does not verify the Gateway
  DB, migrations, tenant registry, adapter runtime, active policies, signing
  keys, or ability to serve an existing organization.
- Outside dev mode, a missing API token does not fail startup. Health remains
  green while protected routes return HTTP 500.
- Gateway migrations 1–4 are explicit and individually transactional, but
  organization + owner + tenant bootstrap is not one transaction.
- SQLite foreign-key clauses exist, but the Gateway connection does not enable
  `PRAGMA foreign_keys=ON`.
- Durable org/user/agent/adapter rows are not sufficient to reconstruct the
  process-local refund runtime after restart.

## UI media audit

The media scripts were inspected end to end. They start a real uvicorn
application in a temporary data directory, run the buyer acceptance journey,
seed pending and verified refunds via the SDK, authenticate Chromium, and
capture the rendered Control Center. The recorder uses Playwright video and
ffmpeg to create MP4/GIF outputs; it does not render mock HTML or manufacture
success images.

A fresh isolated reproduction generated:

| Asset | Fresh result |
|---|---|
| Overview | PNG, `1440x1000`, 152,472 bytes |
| Approval inbox | PNG, `1440x1000`, 96,059 bytes |
| Exact effect/risk/policy | PNG, `1440x2246`, 448,486 bytes |
| Passport | PNG, `1440x1088`, 237,457 bytes |
| Searchable audit | PNG, `1440x1203`, 180,737 bytes |
| MP4 | H.264, `1280x720`, yuv420p, 38.280 seconds, 1,047,558 bytes |
| GIF | Generated successfully, 1,207,565 bytes |

The checked-in screenshots have exactly the same dimensions and visually match
the current pages; hashes appropriately differ because IDs/timestamps are
dynamic. The checked-in MP4/GIF sizes are 1,036,379 and 1,048,483 bytes.

The in-application browser was unavailable in this audit environment (browser
inventory was empty), so reproduction used the repository's standalone
Playwright scripts. Exact historical provenance of checked-in media cannot be
cryptographically proven because the repository has no media build attestation.
The reproducibility and present-feature claims are nevertheless strongly
verified.

The media also visibly confirms a product defect: a `BLOCK` policy decision is
shown alongside approval and a subsequently verified Passport.

## Commands and exact results

All local commands ran from the audited repository unless an isolated
`C:\tmp` path is shown.

The focused command was:

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  tests\integration\test_gateway_api.py `
  tests\integration\test_gateway_refunds.py `
  tests\integration\test_control_center.py `
  tests\integration\test_sdk_client.py `
  tests\integration\test_sdk_async_client.py `
  tests\integration\test_milestone_a_acceptance.py `
  tests\unit\test_gateway_store.py `
  tests\unit\test_acceptance_cli.py `
  tests\unit\test_approval.py `
  tests\adversarial\test_approval_gaming.py `
  tests\adversarial\test_policy_bundle_gaming.py `
  tests\adversarial\test_passport_v2_gaming.py `
  tests\adversarial\test_portable_evidence_gaming.py
```

| Command/check | Exact result |
|---|---|
| Focused Gateway/refund/UI/SDK/approval/policy/Passport/evidence tests | `153 passed, 1 warning in 114.62s` |
| `.\.venv\Scripts\python.exe -m pytest -q` | `910 passed, 8 skipped, 1 warning in 225.71s` |
| `.\.venv\Scripts\python.exe -m pytest --cov=karmasakshi --cov-report=term-missing --cov-report=xml:C:\tmp\ks-coverage-audit-20260730-01\coverage.xml --cov-fail-under=90 -q` | `910 passed, 8 skipped, 1 warning in 301.60s`; total branch-aware coverage `90.42%` |
| `.\.venv\Scripts\python.exe -m ruff check .` | `All checks passed!` |
| `.\.venv\Scripts\python.exe -m ruff format --check .` | `361 files already formatted` |
| `.\.venv\Scripts\python.exe -m mypy src` | `Success: no issues found in 184 source files` |
| `.\.venv\Scripts\python.exe -m bandit -r src\karmasakshi -c pyproject.toml` | Exit 0; no issues; 24,256 lines scanned; 14 explicit skips |
| `.\.venv\Scripts\python.exe -m build --outdir C:\tmp\ks-release-audit-build-20260730` | Built sdist and wheel successfully |
| `.\.venv\Scripts\python.exe -m twine check C:\tmp\ks-release-audit-build-20260730\*` | Wheel and sdist both `PASSED` |
| Isolated base-wheel install | Install, `pip check`, import, CLI help, and acceptance help passed |
| Actual isolated `karmasakshi-acceptance --base-url http://127.0.0.1:1` | Exit 1: `ModuleNotFoundError: No module named 'httpx'` |
| `.\.venv\Scripts\python.exe -m pip_audit` | Exit 1: `pytest 8.4.2`, `PYSEC-2026-1845`, fix `9.0.3` |
| `.\.venv\Scripts\karmasakshi.exe --workspace C:\tmp\ks-readme-demo-audit-20260730-01 demo --all` | `15/15 scenarios behaved as expected` |
| Buyer acceptance in fresh media seed | 25 checks passed; run twice as part of fresh screenshot/video reproduction |
| Docker local | Not run: Docker executable unavailable |
| Exact-tree GitHub Compose CI | Successful run/job described above |

The one recurring local test warning is Starlette's deprecation warning that
`httpx` with `starlette.testclient` is deprecated and `httpx2` should be used.
The eight skips are environment-dependent Redis tests; PR CI ran the test
matrix with a real Redis service.

## Findings

### RA-001 — Critical — Organization ID permits tenant filesystem escape

**Evidence**

- `OrganizationBootstrapIn.org_id` is an unconstrained `str`
  (`gateway/schemas.py:32-43`).
- `MultiTenantControlPlane._build_state()` computes
  `tenant_dir = root / tenant_id` and creates it
  (`tenant/control_plane.py:56-60`).
- A fresh bootstrap using an absolute Windows path as `org_id` returned HTTP
  200 and created `audit.db`, `grants.db`, `ledger.db`, `lifecycle.db`, and
  `outbox.db` outside the configured tenant root.

Exact reproduction:

```text
PATH_TRAVERSAL_BOOTSTRAP_STATUS=200
ESCAPED_DIRECTORY_EXISTS=True
```

On POSIX, an absolute `org_id` similarly discards the preceding root in
`Path / absolute_path`. The endpoint is platform-token protected outside dev
mode, but the shipped loopback Compose evaluation deliberately enables dev
mode. This is arbitrary application-data placement with the privileges of the
server process.

### RA-002 — High — Named volume does not restore the Gateway refund product

**Evidence**

`ApiState` documents and stores sealed manifests, grant maps, commit results,
proofs, assessments, policy bundles, approval statements, active policy, and
signing key in process memory (`api/state.py:43-72`). The payment simulator is
also recreated empty on startup (`api/state.py:79-118`). The tenant registry is
not rebuilt from durable Gateway rows.

Fresh reproduction against the same data directory:

```text
RESTART_BOOTSTRAP_STATUS=200
POST_RESTART_LOGIN_STATUS=200
POST_RESTART_REFUND_RUNTIME_STATUS=500
```

Login works because the Gateway user is durable. The refund route fails because
`resolve_org_runtime()` cannot find the tenant, and its exception mapping does
not handle the resulting unknown-tenant exception. The named volume persists
files, not a usable Milestone A refund journey.

### RA-003 — High — Activated organization policy is ignored during assessment

**Evidence**

Policy activation builds and stores a signed bundle
(`gateway/refunds.py:316-354`). Proposal calls
`state.engine.assess(manifest)` without the active bundle or its policy
(`gateway/refunds.py:399-455`). The active bundle is only looked up later for
grant binding.

Fresh reproduction activated `block_threshold=100` and
`review_threshold=99`, under which score 87 should not be blocked:

```text
ASSESSMENT_POLICY_ID=default
ASSESSMENT_SCORE=87
ASSESSMENT_RECOMMENDATION=block
```

No Gateway test asserts that changing the active organization's thresholds
changes the assessment. The core engine deliberately treats recommendations as
advisory, but the Control Center labels the value “Policy decision,” shows
`BLOCK`, still offers approval, and permits successful execution.

### RA-004 — High — Ambiguous recovery produces contradictory truth surfaces

**Evidence**

The settle-then-timeout simulator returns an unsuccessful ambiguous
`CommitResult`. `commit()` transitions the lifecycle to terminal `FAILED`
(`engine/core.py:1588-1601`). Recovery records an audit event, idempotent
outcome, and outbox confirmation, but makes no lifecycle transition
(`engine/core.py:1632-1670`).

The Gateway read model prioritizes the proof and reports `verified_match`
(`gateway/refunds.py:152-163`), while Passport V2 prioritizes lifecycle
`failed` (`passports/v2.py:43-50`).

Exact reproduction:

```text
AMB_EXEC_SUCCESS=False
BEFORE_LIFECYCLE=failed BEFORE_STATUS=ambiguous BEFORE_AMBIGUOUS=True
RECOVERY_MATCHED=True
AFTER_LIFECYCLE=failed AFTER_STATUS=verified_match AFTER_AMBIGUOUS=False
PASSPORT_OUTCOME=failed
```

Acceptance only asserts that recovery evidence matched; it does not compare
the lifecycle, read model, and Passport.

### RA-005 — High — “Three-person human quorum” has no meaningful user authorization

**Evidence**

The server correctly takes approver identity from the session and rejects a
duplicate user ID (`gateway/refunds.py:463-514`). However,
`POST /organizations/{org_id}/users` checks only organization membership; it
does not require owner/admin role (`gateway/api.py:287-309`). `GatewayUserRole`
is metadata and is never an authorization decision. Any member can create
arbitrary additional accounts, log into them, and satisfy the quorum.

The buyer acceptance command itself creates the additional approver accounts
with the owner session. It therefore proves “three distinct authenticated
accounts,” not “three people” or an independently governed approval group.
`docs/limitations.md` discloses no RBAC/per-user signing keys, but README alt
text and buyer documentation use the stronger human/person claim.

### RA-006 — Medium — Installed acceptance command lacks a required dependency

**Evidence**

The base project installs a `karmasakshi-acceptance` console entry point, but
`httpx` is present only in optional `api`/`sdk` extras. CI's wheel smoke runs
only `karmasakshi-acceptance --help`, before the function's lazy `import httpx`.

In a fresh virtual environment containing the wheel and only declared base
dependencies:

```text
HTTPX_AVAILABLE False
ModuleNotFoundError: No module named 'httpx'
ACCEPTANCE_EXIT=1
```

Docker is unaffected because it installs `.[api]`. README's non-Docker
instruction presents the packaged command without requiring an extra.

### RA-007 — Medium — “Signed Action Passport” is false

**Evidence**

Passport V2 computes `passport_hash`; it has no Passport signature.
`docs/action-passport-v2.md:72-74` explicitly says it is not separately signed.
The seal, grant, keys, and audit are signed/content-bound anchors, but that does
not make the Passport itself a signed credential. The acceptance code labels
check 18 “Signed Action Passport generated,” and the MVP checklist repeats it.

### RA-008 — Medium — Compensation authorization bypasses the refund approval workflow

**Evidence**

Compensation creates a distinct sealed manifest and distinct grant, which is a
real structural protection. However, one authenticated caller invokes one
endpoint that prepares, seals, authorizes, and commits the compensation
(`gateway/refunds.py:689-744`). It does not require the original refund's
assessment-derived quorum or a separate review step.

“Separate authorized effect” is technically true at the protocol object level,
but buyer-facing wording can be read as a separate human authorization
decision. It is not one.

### RA-009 — Medium — Local authentication accepts empty passwords

**Evidence**

Bootstrap and user-create schemas impose no password length requirement, and
the store hashes whatever string is supplied (`gateway/store.py:189-237`).
Fresh reproduction:

```text
EMPTY_OWNER_PASSWORD_BOOTSTRAP_STATUS=200
EMPTY_PASSWORD_LOGIN_STATUS=200
```

The Gateway is expressly local-development authentication, which limits
severity but does not make an empty credential safe.

### RA-010 — Medium — Health/readiness and startup validation can report healthy while unusable

**Evidence**

`/health` is unconditional (`api/routes.py:105-107`). `/ready` checks only the
core audit chain (`api/routes.py:110-123`). Missing API token outside dev mode
is detected only on a protected request, which returns HTTP 500
(`api/auth.py:35-48`). Existing durable organizations are not checked for a
runtime, as RA-002 demonstrates.

Compose gates acceptance on liveness, not product readiness.

### RA-011 — Medium — Fresh dependency audit fails

**Evidence**

Fresh `pip-audit` reports:

```text
pytest 8.4.2  PYSEC-2026-1845  fix: 9.0.3
Found 1 known vulnerability in 1 package
```

Pytest is a development dependency, so this is not a shipped runtime-library
vulnerability. It does make a fresh audit of the actual release-development
environment fail. `pyproject.toml` currently constrains pytest to `<9`,
excluding the reported fixed version. The Security workflow installs
`.[all]`, which does not include the PEP 735 development dependency group, so
its successful `pip-audit --skip-editable` job does not audit pytest. PR #47's
runtime/extra dependency audit was green; the development toolchain was outside
that job's scope.

### RA-012 — Low — Several security/acceptance tests overstate their coverage

**Evidence**

- `test_cross_tenant_access_rejected_on_every_org_scoped_endpoint` exercises a
  subset, not every org-scoped endpoint.
- `test_all_endpoints_require_a_gateway_session` exercises only `/audit`.
- Milestone acceptance asserts `len(report.checks) >= 20` plus only a subset of
  names, not an exact 25-name contract.
- The buyer modified-manifest scenario creates a second changed manifest and
  uses the original grant; deeper same-object tamper checks exist elsewhere,
  but the acceptance label alone is broader than that scenario.
- Ambiguous recovery acceptance does not check consistency across lifecycle,
  read model, and Passport.

The common dependencies and core adversarial suite provide additional real
coverage. The issue is misleading test names and missing regression assertions,
not wholesale absence of security tests.

### RA-013 — Low — README test count is stale

The README's “real run on this branch” block reports 768/8 and 90.37%, then
notes these are Phase 24 figures. Current main is 910/8 and 90.42%. The caveat
prevents this from being fabricated evidence, but its placement under the
current branch heading is misleading.

### RA-014 — Low — Gateway relational/transaction boundaries are incomplete

Foreign-key declarations exist in migrations, but the connection does not
enable SQLite foreign-key enforcement. Organization, owner, and tenant runtime
creation are separate operations without a compensating transaction, so a
later failure can leave partial durable state.

## Unverified claims and explicit limitations

- Docker Compose was not run locally because Docker is not installed. Exact-tree
  CI is the only execution evidence for Compose.
- Redis tests were skipped locally. The exact-head CI test matrix used a real
  Redis service.
- No real bank/payment provider, SSO, MFA, KMS/HSM, multi-node deployment,
  load test, external penetration test, or independent audit was available.
- Checked-in media has reproducible source scripts and fresh visual matches,
  but no cryptographic provenance/build attestation.
- This audit did not formally prove the 74 documented protocol invariants.
- No dead code was conclusively identified. Ruff found no unused imports or
  undefined symbols; low coverage alone was not treated as proof of dead code.

## Failed or misleading release claims

The following claims must not be repeated without qualification:

- “Milestone A local evaluation product complete.”
- “Signed Action Passport.”
- “Three-person” or “human” quorum when only distinct self-provisionable
  accounts are enforced.
- “Simulator data lives in a named volume” if interpreted as restart-safe
  refund state.
- “Policy decision” if the activated policy is not used and a block has no
  enforcement consequence.
- “Ambiguous timeout recovered honestly” as a complete lifecycle claim while
  the read model and Passport disagree.
- The packaged acceptance command works after ordinary base-package install.
- The complete release-development dependency set is audit-clean.

## Exact remediation plan

No item below was implemented during this audit.

1. **Block RA-001 before any release.** Define one canonical organization-ID
   validator, use it in all schema/model/store entry points, reject separators,
   absolute paths, drive prefixes, traversal, Unicode ambiguity, and reserved
   values, resolve the tenant path, and assert it remains a child of the
   configured root. Add Windows and POSIX path-escape tests.
2. **Make bootstrap atomic.** Create organization, owner, and tenant runtime as
   one recoverable unit; enable SQLite foreign keys; add forced-failure rollback
   tests.
3. **Define and implement restart semantics.** Persist/reconstruct tenant
   registry, signing identity, manifests, assessments, policies, approvals,
   grant indexes, commits/proofs, and simulator ledger, or explicitly refuse to
   advertise persistence. Convert unknown runtime to a safe non-500 response.
   Add stop/recreate/login/list/detail/execute/recover acceptance tests.
4. **Connect active policy to assessment.** Verify/unseal the active bundle and
   assess with that exact `IntelligencePolicy`; bind the same bundle hash to the
   grant. Add threshold-difference and policy-expiry/tamper tests.
5. **Choose block semantics explicitly.** Either enforce `BLOCK` server-side or
   label it unmistakably “advisory recommendation” and require a defined
   override authorization/audit reason. Do not show an ordinary approval path
   beside an unexplained block.
6. **Repair ambiguous state reconciliation.** Add a lifecycle representation
   for ambiguous and recovered-committed outcomes, reconcile grant/outbox use,
   and make detail, timeline, Passport, evidence, and audit return one coherent
   truth. Add cross-surface regression assertions.
7. **Add real authorization.** At minimum, restrict user creation and
   approval-policy administration to owner/admin, define eligible approver
   roles/groups, prevent self-provisioning a quorum, and decide whether
   per-user signing keys or an external identity assertion are required.
   Replace “person” with “account” until identity assurance exists.
8. **Separate compensation review.** Expose prepare/request/approve/commit as
   separate lifecycle actions, apply a compensation policy/quorum, and audit
   each decision.
9. **Set password policy.** Enforce reasonable length and bounded input on
   bootstrap/create/login, add password reset/removal/session-revocation
   behavior as required, and keep local-auth limitations prominent.
10. **Fix packaging.** Move `httpx` into base dependencies or move the
    acceptance entry point behind/document an extra. Change CI wheel smoke to
    execute the real command far enough to import all runtime dependencies.
11. **Fix readiness/startup.** Fail startup on non-dev missing auth config;
    make readiness verify Gateway DB/migrations and tenant-runtime
    reconstructability; use readiness for Compose gating.
12. **Resolve the current advisory.** Re-evaluate the pytest `<9` constraint,
    upgrade to a fixed compatible release, and rerun `pip-audit` and the entire
    matrix. Do not suppress the advisory without documented exploitability
    analysis.
13. **Strengthen acceptance contracts.** Assert exactly the documented checks,
    enumerate every org-scoped route for auth/isolation, cover all UI mutation
    CSRF paths, and add restart/policy/ambiguity/RBAC/package regressions.
14. **Correct documentation.** Replace signed-Passport language, distinguish
    account quorum from human identity, document actual durability boundaries,
    update current test counts, and keep media only after the corrected product
    is rerun.
15. **Repeat this release audit.** Require all critical/high findings closed,
    all requested gates including fresh `pip-audit` green, local or equivalent
    Compose acceptance green, and preferably an independent human/security
    review before changing the recommendation.

## Release recommendation

**NO-GO.**

Do not release or promote Milestone A as complete. The core protocol, SDK, real
UI, tests, and reproducible demo are credible foundations, but the critical
filesystem escape and high-severity persistence, policy, authorization, and
recovery inconsistencies are incompatible with even a trustworthy local buyer
evaluation release. Reassess only after the remediation above is implemented
and independently retested.
