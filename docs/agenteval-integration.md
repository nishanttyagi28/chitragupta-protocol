# AgentEval Bridge

`karmasakshi.integrations.agenteval` exports a failed or mismatched
production execution as a **versioned, neutral regression fixture** —
redacted, reproducible information only, never credentials or raw
sensitive data.

## Honest scope statement

**This is not a verified-compatible implementation of any specific
upstream AgentEval schema.** The exact AgentEval fixture format could not
be reliably confirmed at the time this was written. Rather than invent a
compatibility claim, this module defines its own versioned,
self-describing export format (`RegressionFixture`,
`FIXTURE_SCHEMA_VERSION = "1.0"`) as a documented, stable boundary — a real
AgentEval-specific adapter can be layered on top of this later (translating
`RegressionFixture` into whatever AgentEval actually expects) without this
module needing to change.

## Usage

```python
from karmasakshi.integrations.agenteval import export_regression_fixture, write_fixture

fixture = export_regression_fixture(
    manifest=sealed_manifest.manifest,
    failure_category="verification_mismatch",
    commit_result=commit_result,
    outcome_proof=outcome_proof,
    invariant="#20 a successful API response is not proof",
)
write_fixture(fixture, "fixtures/mismatch-1.json")
```

## What's in a fixture

| Field | Content |
|---|---|
| `schema_version` | Fixture format version (independent of the protocol's own schema version) |
| `exported_at` | UTC timestamp |
| `effect_type`, `adapter_id`, `adapter_version` | From the manifest |
| `normalized_inputs` | The manifest's own `parameters` dict — already schema-restricted to `str\|int\|bool\|None` and size-limited, so safe to re-export directly |
| `expected_effect` | `target_resource` and `expected_after_state_digest` |
| `observed_outcome` | `commit_success`, `matched_expected`, `detail` |
| `failure_category` | Caller-supplied classification string |
| `invariant` | Optional: which of the 30 invariants this relates to |
| `reproduction_metadata` | `manifest_hash`, `idempotency_key` — enough to correlate with the audit journal, never a credential |

`tests/unit/test_agenteval_export.py::test_export_contains_no_secrets_or_raw_credentials`
asserts the serialized fixture never contains the substrings `"password"`,
`"secret"`, or `"private_key"` (case-insensitive).

## Demo

`karmasakshi demo --all` scenario 15 constructs a deliberate outcome
mismatch (scenario 12) and exports it as a real fixture file, printing the
path.
