# Build Status — KarmaSakshi Protocol v0.1

_Last updated: 2026-07-27 (final verification pass complete)_

**Status: all 16 planned phases complete.** 272 tests passing, 6 skipped
(documented reasons below), mypy --strict clean, ruff clean, bandit clean,
pip-audit clean, package builds reproducibly, CLI verified from a clean
wheel-only install. See "Final verification results" near the end of this
file for the full command-by-command record.

## Repository state at session start

- Empty git repository, no commits, single branch `master`.
- Working branch created: `feature/karmasakshi-protocol-v0.1`.
- Python available: 3.14.6 (default `python`), 3.12 (via `py -3.12`). Dev venv will target **3.12** for
  best wheel availability (cryptography, pydantic-core) — package metadata will still declare
  `requires-python = ">=3.10,<3.14"`.
- PyPI name check: `https://pypi.org/pypi/karmasakshi-protocol/json` → 404 (name available).
  Distribution name: **karmasakshi-protocol**. Import name `karmasakshi`, CLI `karmasakshi` (unchanged
  per instructions regardless of PyPI name).

## Plan (phases, committed independently)

1. Architecture/spec scaffold, pyproject, repo structure, docs skeleton
2. Domain models + canonical serialization (`domain/`, `canonical/`, `protocol/`)
3. Crypto: Ed25519 keys, signing, verification, grants (`crypto/`, `grants/`)
4. State machine + core engine (`state_machine/`, `engine/`)
5. Storage backends + atomic consumption: memory, sqlite, redis (`stores/`)
6. Delegation attenuation (`delegation/`)
7. Audit journal + Action Passport (`audit/`, `passports/`)
8. Effect adapters: sqlite db, email sandbox, payment simulator (`adapters/`)
9. LangGraph integration (optional dep) (`integrations/langgraph`)
10. CLI (`cli/`)
11. FastAPI control plane + local console (`api/`, `web/`)
12. AgentEval bridge (`integrations/agenteval`)
13. Test hardening / adversarial + property-based suite
14. Documentation (docs/*, README, SECURITY, CONTRIBUTING, etc.)
15. CI, packaging, release prep
16. Final fixes and verification run

## Progress log

- [x] Phase 1: scaffold (pyproject, src layout, LICENSE, .gitignore)
- [x] Phase 2: domain + canonical (EffectManifest, Seal, canonical hashing) -- 24 tests
- [x] Phase 3: crypto + grants (Ed25519 keys/keyring, ExecutionGrant, sealing) -- 36 tests
- [x] Phase 4: state machine + engine (also pulled in: audit journal in-memory,
      GrantStore protocol + in-memory backend, EffectAdapter contract -- these
      were needed for the engine to be real/testable, not stubs) -- 19 tests
      Running total: 104 tests, mypy --strict clean, ruff clean.
- [x] Phase 5: stores (SQLite + Redis backends) -- 11 tests (+6 skipped, no local Redis)
- [x] Phase 6: delegation attenuation + multi-hop chain verification -- 18 tests
- [x] Phase 7: audit SQLite backend + Action Passport -- 15 tests
- [x] Phase 8: adapters (sqlite db, email sandbox, payment simulator) -- 25 tests + 3 e2e
- [x] Phase 9: langgraph integration (pause/resume/authorize) -- 6 tests
- [x] Phase 12: AgentEval bridge -- 5 tests (done early since CLI demo needed it)
- [x] Bugfix: engine.commit() now cryptographically verifies the seal
      (was hash-check only) -- found via the CLI demo suite, regression test added
- [x] Phase 10: CLI (init/key/prepare/seal/grant/execute/verify/compensate/
      audit/passport/demo/doctor/version) -- 11 tests
      Running total: 192 tests passing, 6 skipped (Redis), mypy --strict clean, ruff clean.
- [x] Phase 11: FastAPI control plane + server-rendered console -- 12 tests
- [x] Phase 13: test hardening (property-based x6 files/hypothesis, adversarial
      x2 files, cross-process canonicalization fixtures) -- 46 new tests
      Found and fixed 2 more real gaps this phase:
      1. sqlite store's rollback-inside-except could itself raise on a fully
         dead connection, masking the intended StoreUnavailableError -- fixed
         with a suppress-and-reraise helper.
      2. AuditEvent/target_resource lacked a few adversarial-input guards
         (sequence>=1, non-empty event_id/event_type/decision, control chars
         in target_resource) -- added.
      Running total: 272 tests passing, 6 skipped (Redis), 90% overall
      coverage. protocol/, grants/verifier.py, state_machine/, delegation/
      all at 100%. stores/memory.py 97%, stores/sqlite.py 100%;
      stores/redis_store.py is only 26% covered because no local Redis
      server was available in this environment (documented, not fabricated).
      mypy --strict clean, ruff clean.
- [x] Phase 14: docs -- README rewritten (real problem, runnable example,
      Mermaid architecture + lifecycle diagrams, exact demo output from a
      real run), all 19 required docs/*.md files, SECURITY.md,
      CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md
- [x] Phase 15: CI/packaging -- GH Actions (ci/security/release workflows),
      Dependabot, issue/PR templates, Dockerfile, docker-compose.yml,
      .env.example, release checklist. pip-audit found 15 known CVEs
      (cryptography 43.0.3; langgraph/langchain-core/langgraph-checkpoint/
      langgraph-sdk older pins) -- all fixed by bumping version constraints
      (cryptography >=44,<50; langgraph >=1.0.10,<2; langchain-core >=1.0,<2;
      langgraph-checkpoint >=4.1.1,<5), full suite re-verified green with
      no code changes beyond 2 mypy generic-type-arg annotations for the
      newer langgraph type stubs. `pip-audit` now reports zero known
      vulnerabilities. Reproducible build verified (two separate
      `python -m build` runs produce byte-identical wheel/sdist SHA-256).
- [x] Phase 16: final verification run (see below)

## Final verification results (2026-07-27, this environment)

All commands run for real; results below are from actual command output,
not assumed.

| Command | Result |
|---|---|
| `ruff format --check .` | PASS (138 files already formatted) |
| `ruff check .` | PASS (all checks passed) |
| `mypy src` | PASS (0 errors, 76 source files) |
| `pytest` | PASS (272 passed, 6 skipped) |
| `pytest --cov=karmasakshi --cov-report=term-missing` | PASS, 90% overall coverage |
| `python -m build` | PASS (sdist + wheel built); re-run twice, byte-identical SHA-256 hashes both times |
| `python -m twine check dist/*` | PASS (both artifacts) |
| `pip-audit` | PASS -- 0 known vulnerabilities (15 found and fixed during this phase, see Phase 15 note) |
| `bandit -r src/karmasakshi` | PASS -- 0 issues (12 findings reviewed and suppressed with `# nosec` + comment justifying each: fixed-table-name SQL f-strings, an env-var-name constant, and 5 type-narrowing `assert`s guaranteed safe by preceding logic) |
| `karmasakshi doctor` (fresh workspace) | PASS -- all 6 checks OK |
| `karmasakshi demo --all` | PASS -- 15/15 scenarios, both from the dev venv and from a clean wheel-only install |
| Clean venv + wheel install: `python -c "import karmasakshi; print(karmasakshi.__version__)"` | `0.1.0` |
| Clean venv + wheel install: `karmasakshi version` | `0.1.0` |
| Clean venv + wheel install: `karmasakshi --help` | PASS, all subcommands listed |

**Skipped, with reason (not fabricated as passing):**
- Redis-specific tests (`tests/unit/test_stores_redis.py`, 6 tests) and any
  Redis-backed CI matrix behavior: no local Redis server was reachable at
  `localhost:6379` in this environment. The Redis backend's code
  (`stores/redis_store.py`) is implemented and reviewed but was not
  exercised against a live server in this session. The CI workflow
  (`ci.yml`) does start a real Redis service container, so this gap does
  not apply to CI runs.
- Docker / `docker compose up` verification: the `docker` CLI is not
  installed in this environment (`docker: command not found`). The
  Dockerfile/`docker-compose.yml` were written and reviewed but not
  actually built/run in this session.

## Notes on scope ordering vs. spec's phase list

Spec commit #4 is "state machine and core engine". The engine cannot function
without *some* grant store and audit sink, so a first, real (non-stub)
in-memory AuditJournal and InMemoryGrantStore were implemented in that same
commit. Phase 5 will add SQLite and (optionally, if a local Redis is
reachable) Redis-backed implementations of the same `GrantStore` protocol,
plus dedicated crash-recovery tests. Phase 7 will add a durable audit
backend option and the passport/CLI-facing layer on top of the same
`AuditJournal`/`AuditBackend` abstraction -- no rewrite needed.

## Known scope decisions (recorded up front, not asked as questions)

- Redis backend: implemented with a Lua script for atomic consumption, but integration tests only
  run if a local Redis is reachable (`REDIS_URL` env or localhost:6379 probe). If unavailable, tests
  are `skip`ped with an explicit reason — never silently omitted from the suite.
- LangGraph is an optional extra (`karmasakshi[langgraph]`); core has zero import-time dependency on it.
- FastAPI local console uses server-rendered Jinja2 templates, no JS build pipeline.
- Docker/Compose verification only runs if Docker is available locally; otherwise marked skipped.
- No production security audit or certification claim anywhere in docs.

## Blockers / deferred items

(updated as they occur)
