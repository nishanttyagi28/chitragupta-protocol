# Contributing

Thanks for considering a contribution. This project is young (v0.2.0) and
the process below reflects that — expect it to evolve.

## Getting set up

```bash
git clone <your fork>
cd karmasakshi-protocol
python -m venv .venv
.venv/Scripts/activate   # or source .venv/bin/activate on macOS/Linux
pip install -e ".[all]"
pip install pytest pytest-asyncio pytest-cov hypothesis mypy ruff bandit pip-audit build twine httpx freezegun
pre-commit install
```

## Before opening a PR

```bash
ruff format --check .
ruff check .
mypy src
pytest
pytest --cov=karmasakshi --cov-report=term-missing
```

All four must pass. If you're touching a security-relevant module
(`domain`, `crypto`, `grants`, `engine`, `delegation`, `stores`, `audit`),
add or update tests in the matching category
(`tests/unit`, `tests/property`, `tests/adversarial`) — see
[docs/security-model.md](docs/security-model.md) for the invariant table
these tests are organized around.

## Code standards

- Python 3.10–3.13, fully type-annotated, `mypy --strict` clean.
- Pydantic v2 models for anything crossing a trust boundary
  (`extra="forbid"`, explicit validators — no silent coercion).
- No placeholder implementations, no `TODO` in a code path that's part of
  a security invariant, no tests disabled to make CI green.
- Comments explain *why*, not *what* — if a comment just restates the
  code, delete it.
- Don't invent cryptography. This project uses `cryptography` (Ed25519)
  and nothing home-grown; any change to signing/verification needs a clear
  justification and should still delegate to an established library
  primitive.

## Reporting bugs vs. security issues

Security vulnerabilities: see [SECURITY.md](SECURITY.md) — please do not
open a public issue for these. Everything else: GitHub issues, using the
provided templates.

## Commit style

Meaningful, scoped commits — not "wip" or "fixes." If a change touches
multiple unrelated concerns, split it into multiple commits/PRs.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
