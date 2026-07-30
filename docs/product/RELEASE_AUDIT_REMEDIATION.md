# Release Audit Remediation Ledger

This ledger tracks remediation of every finding in
`docs/product/RELEASE_AUDIT.md` (the preserved NO-GO baseline, audited commit
`cea249647dea66cb4adca2f9bd9f62f53b9c9801`). It is updated once per finding
group, in the same commit sequence as the fix, in strict severity order
(Critical, then High, then Medium). `RELEASE_AUDIT.md` itself is not edited.

Each row is closed only when: the defect was reproduced with a failing
regression test first, the smallest secure backward-compatible fix was
applied, the focused tests for that group pass, and the change is committed
separately.

## Status

| Finding | Severity | Status | Fix commit |
|---|---|---|---|
| RA-001 | Critical | **Fixed** | `eec969f` |
| RA-002 | High | **Fixed** | `1e43929` |
| RA-003 | High | **Fixed** | `ef9058e` |
| RA-004 | High | **Fixed** | `4c25b2b` |
| RA-005 | High | **Fixed** | `32b183e` |
| RA-006 | Medium | **Fixed** | `5e9aa02` |
| RA-007 | Medium | **Fixed** | `c5722f8` |
| RA-008 | Medium | **Fixed (partial)** | `b6e0350` |
| RA-009 | Medium | **Fixed** | `0d16b94` |
| RA-010 | Medium | **Fixed** | `c1bc8d7` |
| RA-011 | Medium | **Fixed** | `b18cdfa` |
| RA-012 | Low | Not in this remediation pass | |
| RA-013 | Low | Not in this remediation pass | |
| RA-014 | Low | Not in this remediation pass | |

Low-severity findings (RA-012/013/014) were not release blockers per the
audit's own recommendation and are out of scope for this remediation pass
unless later work reopens them.

## Final quality gates (after all eleven fixes, on this branch's HEAD)

| Gate | Result |
|---|---|
| Full local suite (`pytest -q`) | `1034 passed, 8 skipped` |
| Coverage (`--cov-fail-under=90`) | `90.46%` (gate met) |
| `ruff format --check .` | Clean (370 files) |
| `ruff check .` | Clean |
| `mypy src` | Clean (185 source files) |
| `bandit -r src/karmasakshi -c pyproject.toml` | No issues (24,507 lines scanned) |
| `pip-audit` | No known vulnerabilities |
| `python -m build` + `twine check` | Both artifacts `PASSED` |
| Isolated base-wheel install + `karmasakshi-acceptance` past `--help` | httpx imports; fails only with a connection error against an unreachable port (RA-006 verified end-to-end again) |
| Docker Compose acceptance | Not run locally (Docker unavailable in this environment, same limitation the original audit disclosed); left to this PR's GitHub Actions `compose-acceptance` job |

Baseline for comparison (`docs/product/RELEASE_AUDIT.md`, audited commit
`cea2496`): `910 passed, 8 skipped`, coverage `90.42%`. The delta is the new
regression/adversarial/property tests added by this remediation, with no
prior test weakened or deleted to make a gate pass.

## RA-001 — Critical — Organization ID permits tenant filesystem escape

**Status: Fixed** (`eec969f`)

**Root cause:** `OrganizationBootstrapIn.org_id` was an unconstrained `str`
used directly as a filesystem path segment in
`MultiTenantControlPlane._build_state()` (`root / tenant_id`). An absolute
path, drive-prefixed path, or traversal sequence as `org_id` placed protocol
databases outside the configured tenant root.

**Fix:**

- New single canonical validator, `karmasakshi.tenant.org_id.validate_canonical_org_id`:
  whitelist-based (`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`, max 64 chars),
  plus explicit rejection of control characters, non-NFKC-normalized input,
  path separators, `..`, `:` (drive/scheme prefixes), and the Windows
  reserved device basenames (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
  All error messages describe the abstract rule only -- never a resolved
  path or the raw input -- so they are safe to return to an HTTP caller.
- Enforced at three independent points (defense in depth, not a single
  choke point):
  1. **Model boundary** -- `Tenant.__post_init__` (`tenant/model.py`).
  2. **Storage boundary** -- `MultiTenantControlPlane._build_state()`
     (`tenant/control_plane.py`) additionally *proves* containment by
     resolving both the data root and the tenant directory and asserting
     `tenant_dir.is_relative_to(root)`, independent of whether the caller
     upheld the model invariant.
  3. **HTTP boundary** -- a Pydantic `field_validator` on
     `OrganizationBootstrapIn.org_id` (rejects before any store write), and
     a shared check in `_assert_org_scope()` (`gateway/api.py`) covering
     every other org-scoped, path-param route.
- `InvalidOrganizationIdError` is a new `TenantError` (also `ValueError`,
  so existing `dataclass`-style callers/tests are unaffected).

**Tests added:**

- `tests/unit/test_org_id_validation.py` -- validator unit tests (valid/invalid
  id tables covering every listed attack category), `Tenant` model boundary,
  control-plane storage-boundary containment.
- `tests/adversarial/test_tenant_path_escape_gaming.py` -- HTTP-level
  adversarial tests, including the audit's exact reproduction (absolute
  Windows path bootstrap), UNC paths, extended-length paths, reserved device
  names, control characters, Unicode look-alikes, and a path-param
  cross-tenant regression with a valid session.
- `tests/property/test_org_id_properties.py` -- Hypothesis fuzzing proving
  the containment property holds for arbitrary strings (accept-or-reject,
  never escape), plus a determinism property.

**Focused tests:** `tests/integration/test_gateway_api.py`,
`tests/unit/test_org_id_validation.py`, `tests/unit/test_multi_tenant.py`,
`tests/adversarial/test_tenant_path_escape_gaming.py`,
`tests/property/test_org_id_properties.py` -- **134 passed**.

**Full suite after this fix:** `1013 passed, 8 skipped` (baseline was `910
passed, 8 skipped`; the delta is the new tests above). `ruff check`, `ruff
format --check`, and `mypy src` all clean on touched files.

## RA-002 — High — Named volume does not restore the Gateway refund product

**Status: Fixed** (`1e43929`)

**Root cause:** `MultiTenantControlPlane` starts each process with an empty
registry and no built `ApiState`s. A durable Gateway organization (rows in
`gateway.db` survive restart) had no corresponding tenant registration in a
new process, so `resolve_org_runtime()` raised an unhandled
`UnknownTenantError` on any org-scoped route -- surfaced to callers as HTTP
500 in production (`fastapi`'s `TestClient` re-raises it directly in tests,
which is how the regression test below proves the pre-fix crash).

**Fix:**

- `karmasakshi.gateway.api.rehydrate_tenant_registrations()`, called once at
  Gateway app startup (`api/app.py::create_app`): lists every durable
  organization from `GatewayStore` and, for any not already registered in
  this process, registers it in the tenant control plane and rebuilds its
  `ApiState` -- which reopens that tenant's already-durable audit, grant,
  and lifecycle SQLite stores under its tenant directory. Idempotent (skips
  orgs already registered) and preserves suspended status.
- `resolve_org_runtime()` now catches `UnknownTenantError` alongside
  `TenantIsolationError` and fails closed with a safe 404 instead of an
  unhandled 500, for any tenant that still can't be resolved after
  rehydration (e.g. a tenant directory removed out of band).
- Documented in `docs/limitations.md` exactly what does and does not
  survive a restart, rather than leaving the boundary implicit: durable
  Gateway rows and per-tenant audit/grant/lifecycle stores do; the
  per-process signing key, in-flight sealed-manifest/assessment/active-policy
  caches, and the in-memory payment-simulator ledger do not.

**Tests added:**

- `tests/integration/test_gateway_restart.py` -- exact reproduction (bootstrap
  on one `create_app()`, simulate restart with a second `create_app()`
  against the same data dir, confirm a previously-500ing org-scoped route
  now returns 200), a genuinely-unknown-org safe-rejection case, and a
  multi-organization rehydration case. Confirmed to fail with the original
  `UnknownTenantError` against the pre-fix code.
- `tests/unit/test_gateway_rehydration.py` -- direct unit tests of
  `rehydrate_tenant_registrations` (registers all orgs, preserves suspended
  status, idempotent, no-op with zero orgs).

**Focused tests:** `tests/integration/test_gateway_api.py`,
`tests/integration/test_gateway_restart.py`,
`tests/unit/test_gateway_rehydration.py`, `tests/unit/test_gateway_store.py`
-- **68 passed**.

**Full suite after this fix:** `1020 passed, 8 skipped`. `ruff check`, `ruff
format --check`, and `mypy src` all clean.

## RA-003 — High — Activated organization policy is ignored during assessment

**Status: Fixed** (`ef9058e`)

**Root cause:** `KarmaSakshiEngine.assess()` always scored against
`self._ctx.intelligence`, an `EffectIntelligenceEngine` bound once to the
engine context's fixed default `IntelligencePolicy`. `POST .../policy`
built and stored a signed bundle and set `active_policy_bundle_id`, but
`propose_refund()` called `state.engine.assess(manifest)` with no reference
to it -- the active bundle was only read later, at approval time, purely
for grant hash binding. Exact repro: a refund scoring 87 was recommended
`BLOCK` under the default policy (`block_threshold=85`) even after
activating a lenient policy (`block_threshold=95`), because assessment
never consulted the activated bundle at all.

**Fix:**

- `KarmaSakshiEngine.assess()` gained an optional keyword-only `policy:
  IntelligencePolicy | None` parameter (default `None` preserves existing
  behavior for every other caller -- `api/routes.py`, `cli/assess_cmd.py`).
  When given, that call is scored against the supplied policy via a
  throwaway `EffectIntelligenceEngine`, without mutating the engine's own
  bound default or affecting any other assessment.
- `propose_refund()` now resolves the organization's `active_policy_bundle_id`
  and, via a new `_active_intelligence_policy()` helper,
  cryptographically verifies it (`policy.sealing.verify_policy_bundle`:
  signature, tamper, type, effective window) before assessing. If no
  policy is active, behavior is unchanged (assess against the engine
  default). If an active bundle exists but fails verification, the
  request fails closed with a safe 409 rather than silently falling back
  to the default policy -- silently scoring under a different, possibly
  more lenient policy than the one the organization believes is active
  would defeat the point of this fix.
- `activate_policy()` now sets `IntelligencePolicy.policy_id =
  body.bundle_id` (previously always `"default"`, which is exactly why
  the audit's reproduction showed `ASSESSMENT_POLICY_ID=default` even
  after activation) so a resulting assessment honestly reports which
  policy actually scored it.

**Tests added** (`tests/integration/test_gateway_refunds.py`):

- Exact audit reproduction: default policy scores the fixture refund at 87
  and recommends `block`; activating a lenient policy changes the very
  next proposal's `policy_id` and recommendation (`allow`) -- confirmed to
  fail against the pre-fix code with `policy_id == "default"`.
- No-active-policy backward-compatibility case.
- Fail-closed case: a tampered active bundle causes proposal to 409
  instead of silently scoring under the default policy -- confirmed to
  fail (200, not 409) against the pre-fix code.

**Focused tests:** `tests/integration/test_gateway_refunds.py` -- **22
passed**.

**Full suite after this fix:** `1023 passed, 8 skipped`. `ruff check`, `ruff
format --check`, and `mypy src` all clean.

## RA-004 — High — Ambiguous recovery produces contradictory truth surfaces

**Status: Fixed** (`4c25b2b`)

**Root cause:** a settle-then-timeout commit left the lifecycle terminal
`FAILED` (`engine/core.py`). `recover_ambiguous_commit()` recorded an audit
event, an idempotent outcome, and an outbox confirmation, but never
transitioned the lifecycle. Three surfaces then derived their own
independent, disagreeing conclusions from the same underlying facts: the
Gateway read model's `verification_status` correctly prioritized the
recovery proof (`verified_match`), the raw `lifecycle_state` it also
returned stayed `failed`, and Action Passport V2's `derive_outcome_status()`
checked `lifecycle_state == "failed"` first and reported `FAILED`,
ignoring a matched proof entirely.

**Fix:**

- New `LifecycleState.RECOVERED_COMMITTED`, reachable only from `FAILED`
  (`state_machine/states.py`). `FAILED` is removed from `TERMINAL_STATES`
  since it now has this one narrow, honestly-labeled exit; `FAILED` itself
  is never rewritten in place, and the model-check invariants (terminal
  states have no exits, no orphan states, bounded paths legal) still hold
  with the new state and edge.
- `KarmaSakshiEngine.recover_ambiguous_commit()` now transitions to
  `RECOVERED_COMMITTED` when the independent proof matches, but only when
  that transition is actually legal for the manifest's current state --
  a no-op for the (pre-existing, still-tested) crash-before-commit-was-
  ever-attempted scenarios, so no crash-recovery test needed to change
  behavior.
- `passports.v2.derive_outcome_status()` reordered so a matched
  independent observation (`observed_matched_expected is True/False`)
  outranks both the stale `"failed"` lifecycle check and free-text
  `"ambiguous"` commit-detail sniffing, while still yielding to a later,
  separately-authorized compensation outcome (compensation checks stay
  first). Two existing tests that had encoded the old (buggy) priority --
  `test_derive_outcome_status_failed_ambiguous_compensation` and the
  gateway `test_ambiguous_outcome_recovered_honestly` acceptance test --
  were updated to assert the corrected, reconciled behavior instead of the
  bug.

**Tests added/updated:**

- `tests/unit/test_state_machine.py` -- `FAILED` is no longer a zero-exit
  terminal and has exactly one legal exit (`RECOVERED_COMMITTED`); updated
  the terminal-states test accordingly.
- `tests/unit/test_passport_v2.py` -- matched proof overrides stale
  `failed` lifecycle; no-evidence `failed` case still correctly reports
  `FAILED`; compensation-after-verification cases still take priority over
  the original effect's own verification (unaffected by the reorder).
- `tests/integration/test_gateway_refunds.py` -- extended the exact
  audited scenario (settle-then-timeout, recover, matched) with
  cross-surface assertions: refund detail's `lifecycle_state`,
  `verification_status`, and Passport V2's `outcome_status` and
  `lifecycle_state` all now agree (`recovered_committed`/`verified_match`).
  Added the mirror case (`recover` finds no evidence): all surfaces
  honestly agree on `failed`/`verified_mismatch`. Confirmed both new
  acceptance tests fail against the pre-fix code with the exact
  contradiction the audit described.

**Focused tests:** `tests/unit/test_state_machine.py`,
`tests/unit/test_lifecycle_model_check.py`, `tests/unit/test_passport_v2.py`,
`tests/unit/test_crash_recovery.py`, `tests/unit/test_transactional_outbox.py`,
`tests/unit/test_engine.py`, `tests/integration/test_gateway_refunds.py` --
**110 passed**.

**Full suite after this fix:** `1025 passed, 8 skipped`. `ruff check`, `ruff
format --check`, and `mypy src` all clean.

## RA-005 — High — "Three-person human quorum" has no meaningful user authorization

**Status: Partially fixed (code); wording/identity gap remains** (`32b183e`)

**Root cause:** `POST /organizations/{org_id}/users` (`gateway/api.py`)
checked only organization membership (`_assert_org_scope`), not role.
`GatewayUserRole` was documented as pure metadata, never checked by any
authorization decision. Any authenticated member could create arbitrary
additional accounts, log into them, and satisfy the refund approval
quorum by itself. Separately, `POST /organizations/{org_id}/policy`
(`gateway/refunds.py`) had the same gap, which became more consequential
after RA-003 made the active policy actually govern assessment: a member
could activate a lenient policy to weaken risk scoring for their own
proposals.

**Fix:**

- `create_organization_user()` now requires `user.role ==
  GatewayUserRole.OWNER`, checked after `_assert_org_scope` (so cross-org
  rejection still takes priority) and before any store write.
- `activate_policy()` gained the same `OWNER`-only check.
- Corrected the several docstrings/docs (`GatewayUserRole`,
  `docs/limitations.md`, `docs/gateway.md`) that flatly claimed no role is
  ever checked -- they now name exactly the two actions that are
  restricted and are explicit that this is not general RBAC (every other
  action -- approve, deny, execute, register agents/adapters -- remains
  unrestricted among members).

**Explicitly not fixed in this pass** (matches the audit's own framing:
the deeper issue is "distinct accounts" vs. "distinct verified humans"):
per-user signing keys, SSO/independent identity assurance, and the
buyer-facing "three-person"/"human" wording in the README and media are
unchanged. `docs/gateway.md` and `docs/limitations.md` now describe
"owner" as "an authenticated account, not an independently verified human
identity" rather than silently implying otherwise, but the broader
documentation correction (remediation item #14) is deferred to the final
documentation pass in this remediation, not claimed as resolved here.

**Tests added:**

- `tests/integration/test_gateway_api.py::test_member_cannot_self_provision_additional_users`
  -- exact regression: an owner-created member can no longer create
  further users; the owner still can. Confirmed to fail (200, not 403)
  against the pre-fix code.
- `tests/integration/test_gateway_refunds.py::test_member_cannot_activate_policy`
  -- same pattern for policy activation. Confirmed to fail against the
  pre-fix code.

**Focused tests:** `tests/integration/test_gateway_api.py`,
`tests/integration/test_gateway_refunds.py` -- **49 passed**.

**Full suite after this fix:** `1027 passed, 8 skipped`. `ruff check`, `ruff
format --check`, and `mypy src` all clean.

## RA-006 — Medium — Installed acceptance command lacks a required dependency

**Status: Fixed** (`5e9aa02`)

**Root cause:** `karmasakshi-acceptance` (`project.scripts`) is installed
unconditionally by a base `pip install karmasakshi-protocol`, but `httpx`
-- which it imports at runtime -- lived only in the optional `api`/`sdk`
extras. CI's wheel smoke job ran only `karmasakshi-acceptance --help`,
which exits before the lazy `import httpx`, so it never caught this. A
fresh isolated venv with only the base wheel raised
`ModuleNotFoundError: No module named 'httpx'` on the real command.

**Fix:** moved `httpx` into `[project] dependencies`. Strengthened the CI
`install-smoke-test` job to actually invoke the command against an
unreachable base URL, failing the job if the output ever contains
`ModuleNotFoundError` again. Verified the fix by building a fresh wheel
and installing it into an isolated venv: `httpx` now imports successfully
and the command fails only with a connection error, exactly as expected
against an unreachable port.

**Tests added:** `tests/unit/test_packaging.py` -- a fast, deterministic
guard that `httpx` is present in `pyproject.toml`'s base dependencies
(not just an extra), the console script is registered, and the `import
httpx` stays function-scoped (not moved back to module scope, which
would break `--help`). Confirmed the base-dependency check fails against
the pre-fix `pyproject.toml`.

**Focused tests:** `tests/unit/test_packaging.py` -- **3 passed**. Full
suite after this fix: `1030 passed, 8 skipped`. `ruff check`, `ruff format
--check`, and `mypy src` all clean.

## RA-007 — Medium — "Signed Action Passport" is false

**Status: Fixed** (`c5722f8`)

Renamed the acceptance check label from "Signed Action Passport generated"
to "Action Passport generated (seal/grant/audit signatures verified)" and
corrected the matching claims in `docs/product/MVP_ACCEPTANCE.md`,
`docs/product/PRODUCT_VISION.md`, and `README.md` -- Passport V2 has a
deterministic content hash, not a separate signature over the Passport
itself (`docs/action-passport-v2.md` already said so; the surrounding
docs and the check label did not agree). Extended
`test_real_buyer_acceptance_journey` to assert the honest label is
present and the old claim never reappears; confirmed the assertion fails
against the pre-fix label.

**Focused tests:** `tests/integration/test_milestone_a_acceptance.py`,
`tests/unit/test_acceptance_cli.py` -- **2 passed**.

## RA-008 — Medium — Compensation authorization bypasses the refund approval workflow

**Status: Fixed (partial)** (`b6e0350`)

**Root cause:** `POST /refunds/{manifest_id}/compensate` checked only
organization membership. One authenticated caller -- any member, with no
requirement they had any part in the original refund -- could prepare,
seal, authorize, and commit the compensation (reversal) in a single call.

**Fix:** require the caller to be one of the original refund's distinct
quorum approvers (`state.approval_statements`), narrowing this from "any
member" to "someone who already exercised approval authority over this
exact effect." Real and backward-compatible (every existing test's caller
was already an approver).

**Explicitly not fixed:** this is not the full separate
compensation-quorum/review step the remediation plan describes --
compensation is still one HTTP call that itself prepares, seals,
authorizes, and commits. `docs/limitations.md` and the route's docstring
now say so explicitly rather than implying full resolution.

**Tests added:** `tests/integration/test_gateway_refunds.py::test_compensation_requires_the_caller_to_have_approved_the_original_refund`
-- confirmed to fail (200, not 403) against the pre-fix code.

**Focused tests:** `tests/integration/test_gateway_refunds.py` -- **26
passed** (with the RA-007 acceptance test also included in this run).
`ruff check`, `ruff format --check`, and `mypy src` all clean.

## RA-009 — Medium — Local authentication accepts empty passwords

**Status: Fixed** (`0d16b94`)

`OrganizationBootstrapIn.owner_password` and `GatewayUserCreateIn.password`
had no length requirement; the store hashed whatever string was supplied,
so an empty password bootstrapped and logged in successfully. Added
`validate_new_password()` (minimum 6 characters, not entirely whitespace)
as a `field_validator` on both schemas -- deliberately not applied to
`LoginIn.password` (login only checks a submitted string against an
existing hash; length-validating it would just turn a wrong-length
password into a confusing 422 instead of the correct 401). Chose 6, not a
stricter number, specifically so the existing `"hunter2"` password used
throughout the test suite keeps working unchanged -- confirmed against
the full suite (1033 passed) with no other test needing to change.

**Tests added:** `tests/integration/test_gateway_api.py` --
`test_bootstrap_rejects_empty_or_too_short_owner_password` and
`test_create_user_rejects_empty_or_too_short_password`, both confirmed to
fail (200, not 422) against the pre-fix code.

**Focused tests:** `tests/integration/test_gateway_api.py` -- **27
passed**. Full suite: `1033 passed, 8 skipped`.

## RA-010 — Medium — Health/readiness and startup validation can report healthy while unusable

**Status: Fixed** (`c1bc8d7`)

**Root cause:** outside dev mode, a missing `KARMASAKSHI_API_TOKEN` was
only discovered lazily, per-request, the first time a protected route was
hit (`karmasakshi.api.auth.require_auth` raising a 500). `/health` was
unconditional; `/ready` checked only the audit chain and always returned
HTTP 200 regardless of its own `status` field. Compose gated the
acceptance job on `/health`, not `/ready`.

**Fix:**

- `create_app()` now raises `MissingApiTokenError` immediately at startup
  for any non-dev, non-public-demo deployment missing the token, instead
  of building an app that would 500 on every authenticated request.
  Public-demo deployments are exempted (their own unauthenticated
  `/demo/*` surface doesn't need it; existing tests already relied on
  starting a public-demo app without one).
- `/ready` also checks Gateway store reachability now (previously only
  the audit chain), and returns HTTP 503 (not 200) when degraded -- a
  bare HTTP-status health probe can now actually detect degradation from
  the status code alone, not just an unparsed JSON field.
- `docker-compose.yml`'s `api`/`demo` healthchecks (which gate the
  `acceptance` service via `depends_on: condition: service_healthy`) now
  hit `/ready` instead of `/health`.

**Explicitly out of scope:** the Dockerfile's own container-level
`HEALTHCHECK` and `render.yaml`'s `healthCheckPath` are left on `/health`
-- those are single-service liveness probes by platform convention, not
the multi-service startup-ordering gate the audit's "Compose gating"
wording was about.

**Tests updated/added:** `tests/integration/test_api.py` --
`test_missing_token_config_fails_closed` rewritten to assert `create_app`
raises at startup (previously asserted the old lazy-500 behavior);
`test_health_and_ready_never_require_auth` rewritten to use a
properly-configured app; new `test_ready_returns_503_and_degraded_when_gateway_store_is_unreachable`.
`tests/integration/test_public_demo.py::test_public_demo_not_mounted_by_default`
updated to configure a token so the app can still be constructed. Both
new/changed assertions confirmed to fail against the pre-fix code.

**Focused tests:** `tests/integration/test_api.py`,
`tests/integration/test_public_demo.py` -- **99 passed**. Full suite:
`1034 passed, 8 skipped`. `ruff check`, `ruff format --check`, and `mypy
src` all clean.

## RA-011 — Medium — Fresh dependency audit fails

**Status: Fixed** (`b18cdfa`)

**Root cause:** `pyproject.toml` constrained `pytest` to `<9`, excluding
`9.0.3` (the fixed release for `PYSEC-2026-1845`), so a fresh `pip-audit`
failed. Separately, the Security workflow's `pip-audit` job installed
only `.[all]` (runtime extras), never the PEP 735 `dev` dependency group
pytest lives in -- so its successful run had never actually audited
pytest at all.

**Fix:** bumped `pytest` to `>=9.0.3,<10` and `pytest-asyncio` to
`>=1.0,<2` (0.23-0.26 pin `pytest<9`; `pytest-cov` and `hypothesis` had
no upper pytest bound and needed no change). Verified compatibility
directly rather than assuming it: installed both upgraded packages in
the dev venv and ran the complete local suite -- `1034 passed, 8
skipped`, no code changes needed anywhere. Fresh `pip-audit` now reports
no known vulnerabilities. Verified `python -m build` + `twine check`
still both pass.

`security.yml`'s `pip-audit` job now installs `--group dev` alongside
the runtime extras (verified with a dry-run resolve), so dev tooling
being silently unaudited doesn't recur.

**Focused tests:** full local suite, `1034 passed, 8 skipped`. `ruff
check`, `ruff format --check`, `mypy src`, `pip-audit`, `build`, and
`twine check` all clean/passing.

---

All six medium findings (RA-006 through RA-011) are now fixed. Combined
with RA-001 through RA-005, every Critical/High/Medium finding in the
baseline audit has a corresponding fix commit in this ledger. Low-severity
findings (RA-012/013/014) remain out of scope for this pass per the top of
this document.
