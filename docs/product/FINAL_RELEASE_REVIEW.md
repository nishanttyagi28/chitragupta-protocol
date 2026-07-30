# Final Release Review — KarmaSakshi Protocol Milestone A

**Review date:** 2026-07-30  
**Reviewed commit (local `main`):** `99c6ec745dbc94ee4f2aa6453dbd100c4f3f25f0`  
**Commit subject:** `Merge pull request #49 from nishanttyagi28/fix/ra002-and-policy-binding-gaps`  
**Environment:** Windows 11, Python 3.12.10 (`.venv`), PowerShell; Docker Engine **not** installed locally  
**Reviewer method:** independent verification of repository + GitHub state; fresh adversarial Gateway reproductions; full local quality gates; buyer acceptance against a real uvicorn process; CI evidence for the exact merge commit

This document is the final release review after PR #49. It does **not** rewrite the historical baseline audit. The original NO-GO remains in `docs/product/RELEASE_AUDIT.md` (audited commit `cea2496`). Remediation history is in `docs/product/RELEASE_AUDIT_REMEDIATION.md` and `docs/product/POST_REMEDIATION_AUDIT.md`.

## Orientation (verified)

| Check | Result |
|---|---|
| Branch | `main` |
| Local HEAD | `99c6ec7` |
| `origin/main` | Equal to local HEAD (fast-forward already synchronized) |
| Working tree at review start | Clean |
| Open remediation / release-review PRs | None |
| PR #49 | **MERGED** 2026-07-30T08:46:17Z; merge commit `99c6ec7` |
| PR #48 | **MERGED** (original Critical/High/Medium remediation) |
| `docs/product/RELEASE_AUDIT.md` recommendation | Still **NO-GO** (historical baseline; not rewritten) |
| README tagline | `संकल्प प्रमाण` |
| README positioning | `Runtime trust infrastructure for consequential AI-agent actions` |

## Exact commands executed

```text
git fetch origin
git status -sb
git rev-parse HEAD
gh pr view 49 --json state,mergedAt,mergeCommit,url
gh run list --commit 99c6ec745dbc94ee4f2aa6453dbd100c4f3f25f0
gh run view 30528000335 / 30528000292  # CI + Security on merge commit

# Fresh adversarial A/B/C scripts (fastapi.testclient + create_app, not only committed tests)
python -c "<standalone A/B/C reproduction>"

pytest --cov=karmasakshi --cov-fail-under=90 -q -rs
ruff check .
ruff format --check .
mypy src
bandit -r src/karmasakshi -c pyproject.toml
pip-audit --skip-editable
python -m build
python -m twine check dist/*
# isolated venv (Python 3.12): pip install dist/*.whl; import; karmasakshi version; acceptance --help
KARMASAKSHI_API_DEV_MODE=1 uvicorn karmasakshi.api.app:create_app --factory --port 8777
karmasakshi-acceptance --base-url http://127.0.0.1:8777 --report artifacts/final-release-review-acceptance.json
karmasakshi version
karmasakshi --help
```

## Quality-gate results (this review, on `99c6ec7`)

| Gate | Result |
|---|---|
| Full pytest | **1049 passed, 8 skipped** |
| Coverage | **90.49%** (threshold 90% met; prior post-remediation note 90.50% — normal run variance) |
| `ruff check` | Clean |
| `ruff format --check` | Clean (372 files) |
| `mypy src` | Clean (186 source files) |
| Bandit | Exit 0 (no issues) |
| `pip-audit --skip-editable` | No known vulnerabilities |
| `python -m build` | `karmasakshi_protocol-0.1.0` sdist + wheel built |
| Twine check | Both artifacts **PASSED** |
| Isolated wheel install (Py 3.12) | Import OK; `karmasakshi version` → `0.1.0`; `karmasakshi-acceptance --help` OK |
| CLI smoke | `karmasakshi version` / `--help` OK against editable + wheel installs |
| Buyer acceptance | **25/25 PASS** (report: `artifacts/final-release-review-acceptance.json`) |
| Docker Compose acceptance (local) | **Not run** — Docker not available on this host |
| Docker Compose acceptance (CI) | **success** on merge commit — job `Docker Compose buyer acceptance` in [CI run 30528000335](https://github.com/nishanttyagi28/karmasakshi-protocol/actions/runs/30528000335) |

### Exact skip reasons (8)

All Redis integration tests skipped because no Redis is reachable at `localhost:6379` (connection timed out):

1. `tests/unit/test_audit_redis.py:51`
2. `tests/unit/test_audit_redis.py:59`
3. `tests/unit/test_stores_redis.py:54`
4. `tests/unit/test_stores_redis.py:61`
5. `tests/unit/test_stores_redis.py:67`
6. `tests/unit/test_stores_redis.py:74`
7. `tests/unit/test_stores_redis.py:80`
8. `tests/unit/test_stores_redis.py:97`

CI test matrix jobs that start Redis still run these paths on Linux.

## CI evidence (exact merge commit `99c6ec7`)

**CI** run [30528000335](https://github.com/nishanttyagi28/karmasakshi-protocol/actions/runs/30528000335) — **success**

| Job | Conclusion |
|---|---|
| Lint (ruff) | success |
| Type check (mypy) | success |
| Test (py3.10) | success |
| Test (py3.11) | success |
| Test (py3.12) | success |
| Test (py3.13) | success |
| Coverage | success |
| Build package | success |
| Install wheel + demo smoke test | success |
| Documentation checks | success |
| Docker Compose buyer acceptance | success |

**Security** run [30528000292](https://github.com/nishanttyagi28/karmasakshi-protocol/actions/runs/30528000292) — **success**

| Job | Conclusion |
|---|---|
| Bandit static analysis | success |
| Dependency audit (pip-audit) | success |
| CodeQL | success |

## Release-critical invariants

### A — Durable refund recovery — **PASS**

Fresh script (two successive `create_app(data_dir=...)` calls):

- Propose → approve to quorum → execute → verify → Passport → audit search
- After restart: detail `200` with `commit_success=true` and `verification_status=verified_match`
- Refund present in list
- Passport `seal_verified`, `grant_verified`, `audit_chain_verified` all true; `outcome_status=verified_match`
- Audit searchable with non-empty events
- Idempotent re-execute returns `200`/`409` without manufacturing a replacement identity
- Tenant signing public key identical pre/post restart
- Control Center login page serves (`/control-center/login`)

### B — Proposal-time policy binding — **PASS**

- Activate policy A; propose under A (`assessment.policy_id == policy-a`)
- Activate policy B; approve binds grant `policy_bundle_hash` to **A**, not B
- Activate policy C; execute still succeeds under A's frozen hash
- Across restart: propose under A2, switch policy, restart, approve still binds A2

### C — Tenant signing-key durability — **PASS**

- Distinct keys per tenant; restored (not regenerated) after restart
- Pre-restart Passports verify after restart; propose under active policy works post-restart
- Cross-tenant refund reads fail closed (`403`/`404`)
- Missing key with durable artifacts → `KeyLoadError` at startup (no silent regen)
- Corrupt key → `KeyLoadError`
- Mismatched private key vs `signing-key.pub` → `KeyLoadError`
- Clean first-start generates key + public sidecar; second load restores same key

### D — Commercial acceptance journey — **PASS (25/25)**

`karmasakshi-acceptance` against live Gateway on port 8777 drove API, SDK, and authenticated Control Center surfaces, including:

- org bootstrap, auth, agent/adapter registration, policy activation
- propose, risk assessment, human quorum, commit, independent verify
- modified-amount grant reuse rejection, duplicate retry `409`
- Action Passport generation (seal/grant/audit verified)
- audit search, ambiguous timeout recovery, compensation as separate effect
- offline passport/audit verification, cross-tenant `403`, org audit chain verify

Provider status came from independent ledger observation (`settled`), not a hardcoded success path.

## Supported product claims (evidence-backed)

- Evaluation-ready **self-hosted** Milestone A refund vertical slice exists
- Lifecycle **PROPOSE → PREPARE → ASSESS → SEAL → AUTHORIZE → COMMIT → VERIFY → PROVE** is implemented for the payment-simulator refund path
- Gateway, typed sync/async SDK, Control Center, and 25-check acceptance command ship
- Restart against the same data directory restores org credentials, refund journey state, Passports, audit evidence, active policy, and per-tenant signing identity
- Proposal-time policy hash binding holds across later policy activation and restart
- Missing/corrupt/mismatched signing-key state fails closed for existing tenant data
- Package builds cleanly; base wheel imports and exposes CLI + acceptance entry points
- CI (Python 3.10–3.13, lint, types, coverage, Compose acceptance, security) green on merge commit

## Unsupported claims (do not assert)

- Production readiness, production proven, “enterprise grade”
- Certification (SOC 2, ISO 27001, PCI-DSS, HIPAA, etc.)
- Formal verification or mathematical proof of all security invariants
- Real bank / payment-provider / mail-provider integrations
- Full production IAM, SSO, or complete enterprise RBAC
- Guaranteed compensation / rollback of irreversible effects
- That Effect Intelligence `BLOCK` recommendations alone enforce deny-by-default in the Control Center commit path without human process
- That the historical original release audit was GO (it remains NO-GO)

## Known limitations (still true)

- Payment simulator **account balances** are process-local and reset on restart; Gateway/protocol evidence of what happened does not
- Local evaluation authentication is password + session tokens, not production IAM/SSO/RBAC
- Compensation is a separate authorized effect and may fail (acceptance recorded `succeeded=False` for simulator reverse-settled case); not a full multi-party quorum journey (RA-008 partial)
- No third-party security audit, formal proof, or real payment provider
- Low-severity original findings RA-012–014 remain out of scope
- Root `BUILD_STATUS.md` is a **historical early-phase ledger** (stale test counts); product status lives under `docs/product/BUILD_STATUS.md`
- Docker Compose was not re-run on this Windows host; CI Linux evidence is authoritative for Compose

## Documentation accuracy notes

| Document | Status in this review |
|---|---|
| `README.md` | Tagline, positioning, evaluation-ready wording, gates, limitations: consistent with evidence |
| `docs/product/RELEASE_AUDIT.md` | Historical NO-GO preserved |
| `docs/product/RELEASE_AUDIT_REMEDIATION.md` | Residual ledger present |
| `docs/product/POST_REMEDIATION_AUDIT.md` | Third-pass GO for evaluation-ready |
| `docs/product/BUILD_STATUS.md` / `MVP_ACCEPTANCE.md` / `BUYER_EVALUATION.md` | Align with evaluation product |
| `CHANGELOG.md` Unreleased header | Said “Milestone A in progress” — **stale wording** relative to current main; corrected in the same docs PR as this file if shipped with the review |

## Defects corrected by this review

**None at Critical/High.** No product code changes required.

Narrow documentation only: add this file; correct stale CHANGELOG Unreleased header wording.

## Final recommendation

### **GO** — evaluation-ready self-hosted software

Conditions already satisfied on reviewed main:

- No unresolved Critical/High release blockers in invariants A–D
- Local quality gates green
- Buyer acceptance 25/25
- Merge-commit CI and Security workflows fully green, including Linux Docker Compose acceptance

This is **not** approval to:

- publish to PyPI
- create a Git tag
- create a public GitHub Release
- claim production readiness

Those require explicit human approval after this review.

## Exact next manual release decision

Human owner chooses **one** of:

1. **Ship evaluation artifact as-is on `main`** (no tag/PyPI) and communicate evaluation-ready self-hosted status with documented limitations; or  
2. **Approve a version tag + optional GitHub Release notes** (still no production claims); or  
3. **Approve PyPI publication** of `karmasakshi-protocol` `0.1.0` after re-reading limitations and license; or  
4. **Defer public packaging** and keep private evaluation use only.

Do **not** start Milestone B or the saved 40x expansion from this review.
