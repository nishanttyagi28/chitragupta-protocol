# Adversarial and Fuzz Testing (extreme-v2 Phase 21)

Expanded Hypothesis property tests and adversarial gaming cases for
tenant isolation and resource-protection fail-closed behaviour, in
addition to the per-phase adversarial suites already present under
`tests/adversarial/`.

## New coverage

| Suite | Focus |
|---|---|
| `tests/property/test_phase21_fuzz_properties.py` | Tenant match symmetry/uncertainty; Content-Length monotonicity; rate-limiter over-admit refusal |
| `tests/adversarial/test_phase21_gaming.py` | Whitespace/case tenant lookalikes; empty-string mismatch |

## Honesty limits

- Hypothesis examples are bounded (not exhaustive state-space search).
- This phase does **not** claim formal verification or AFL/libFuzzer
  harnesses against native code.
- Pre-existing Phase 1–20 adversarial suites remain the primary
  surface-specific coverage.
