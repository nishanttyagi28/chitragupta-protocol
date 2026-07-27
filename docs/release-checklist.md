# Release Checklist

1. Update `CHANGELOG.md` with the new version's notes.
2. Bump the version in `pyproject.toml` (`[project].version`) and
   `src/chitragupta/__init__.py` (`__version__`) — they must match.
3. Run the full local verification pass (see README/CI for the exact
   commands): `ruff format --check .`, `ruff check .`, `mypy src`,
   `pytest`, `pytest --cov=chitragupta --cov-report=term-missing`,
   `python -m build`, `python -m twine check dist/*`, `pip-audit`,
   `bandit -r src/chitragupta`.
4. Confirm CI is green on `main` for the commit being released.
5. Tag the release: `git tag vX.Y.Z && git push origin vX.Y.Z`. This
   triggers `.github/workflows/release.yml`, which builds the package and
   then waits for approval on the `pypi` GitHub Environment (configure
   required reviewers there) before publishing via Trusted Publishing
   (OIDC) — no token is stored in the repository.
6. After the tag is pushed and the release workflow succeeds, create a
   GitHub Release from the tag with the relevant `CHANGELOG.md` section as
   the release notes.
7. Verify the published package: `pip install chitragupta-protocol==X.Y.Z`
   in a clean virtualenv, then `python -c "import chitragupta; print(chitragupta.__version__)"`
   and `chitragupta doctor`.

None of steps 5-7 happen automatically from a local `git push` to `main` —
publishing requires an explicit tag push and environment approval, by
design (see `docs/deployment.md` and the comments in
`.github/workflows/release.yml`).
