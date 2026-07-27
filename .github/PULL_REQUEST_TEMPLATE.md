## Summary

<!-- What does this change, and why? -->

## Checklist

- [ ] `ruff format --check .` and `ruff check .` pass
- [ ] `mypy src` passes
- [ ] `pytest` passes
- [ ] Coverage did not regress for touched modules (`pytest --cov=chitragupta --cov-report=term-missing`)
- [ ] If this touches a security-relevant module (`domain`, `crypto`,
      `grants`, `engine`, `delegation`, `stores`, `audit`), tests were
      added/updated in the matching category (unit / property / adversarial)
- [ ] Documentation updated if behavior, an invariant, or a public API changed
- [ ] No `TODO` left in a security-relevant code path
- [ ] No test disabled/skipped to make CI pass

## Related invariant(s)

<!-- If applicable, link the row(s) in docs/security-model.md this touches. -->

## Test plan

<!-- How did you verify this works? -->
