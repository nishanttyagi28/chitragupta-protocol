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
| RA-005 | High | Pending | |
| RA-006 | Medium | Pending | |
| RA-007 | Medium | Pending | |
| RA-008 | Medium | Pending | |
| RA-009 | Medium | Pending | |
| RA-010 | Medium | Pending | |
| RA-011 | Medium | Pending | |
| RA-012 | Low | Not in this remediation pass | |
| RA-013 | Low | Not in this remediation pass | |
| RA-014 | Low | Not in this remediation pass | |

Low-severity findings (RA-012/013/014) were not release blockers per the
audit's own recommendation and are out of scope for this remediation pass
unless later work reopens them.

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
