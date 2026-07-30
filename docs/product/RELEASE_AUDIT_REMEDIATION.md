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
| RA-002 | High | Pending | |
| RA-003 | High | Pending | |
| RA-004 | High | Pending | |
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
