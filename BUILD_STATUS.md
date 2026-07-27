# Build Status — Chitragupta Protocol v0.1

_Last updated: 2026-07-27 (session start)_

## Repository state at session start

- Empty git repository, no commits, single branch `master`.
- Working branch created: `feature/chitragupta-protocol-v0.1`.
- Python available: 3.14.6 (default `python`), 3.12 (via `py -3.12`). Dev venv will target **3.12** for
  best wheel availability (cryptography, pydantic-core) — package metadata will still declare
  `requires-python = ">=3.10,<3.14"`.
- PyPI name check: `https://pypi.org/pypi/chitragupta-protocol/json` → 404 (name available).
  Distribution name: **chitragupta-protocol**. Import name `chitragupta`, CLI `chitragupta` (unchanged
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

- [ ] Phase 1: scaffold
- [ ] Phase 2: domain + canonical
- [ ] Phase 3: crypto + grants
- [ ] Phase 4: state machine + engine
- [ ] Phase 5: stores
- [ ] Phase 6: delegation
- [ ] Phase 7: audit + passport
- [ ] Phase 8: adapters
- [ ] Phase 9: langgraph
- [ ] Phase 10: CLI
- [ ] Phase 11: FastAPI + console
- [ ] Phase 12: AgentEval bridge
- [ ] Phase 13: test hardening
- [ ] Phase 14: docs
- [ ] Phase 15: CI/packaging
- [ ] Phase 16: final verification

## Known scope decisions (recorded up front, not asked as questions)

- Redis backend: implemented with a Lua script for atomic consumption, but integration tests only
  run if a local Redis is reachable (`REDIS_URL` env or localhost:6379 probe). If unavailable, tests
  are `skip`ped with an explicit reason — never silently omitted from the suite.
- LangGraph is an optional extra (`chitragupta[langgraph]`); core has zero import-time dependency on it.
- FastAPI local console uses server-rendered Jinja2 templates, no JS build pipeline.
- Docker/Compose verification only runs if Docker is available locally; otherwise marked skipped.
- No production security audit or certification claim anywhere in docs.

## Blockers / deferred items

(updated as they occur)
