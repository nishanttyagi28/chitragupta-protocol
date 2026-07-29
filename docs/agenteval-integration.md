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

## Failure-memory loop (extreme-v2 Phase 25)

`karmasakshi.integrations.agenteval.memory` adds a durable, portable
memory of previously exported failures on top of the fixture format
above: `FailureMemoryStore` (an append-only JSON-Lines file) groups
recorded fixtures by a deterministic **failure signature** —
`effect_type` + `adapter_id` + `failure_category` + `invariant` — and
answers "have we seen a failure shaped like this before, and how often."

```python
from karmasakshi.integrations.agenteval import FailureMemoryStore, export_regression_fixture

fixture = export_regression_fixture(
    manifest=sealed_manifest.manifest,
    failure_category="verification_mismatch",
    commit_result=commit_result,
    outcome_proof=outcome_proof,
    invariant="#20 a successful API response is not proof",
)
store = FailureMemoryStore("agenteval-memory.jsonl")
store.record(fixture)
store.recurrence_count(
    effect_type=fixture.effect_type,
    adapter_id=fixture.adapter_id,
    failure_category=fixture.failure_category,
    invariant=fixture.invariant,
)  # -> how many times this exact failure shape has been recorded
store.summarize()  # -> FailureMemorySummary per distinct signature, most recurrent first
```

### Honest scope statement

**This is advisory only, like the Effect Intelligence Engine
(docs/effect-intelligence.md) and the fixture export itself.** Nothing in
`karmasakshi.engine` reads from or writes to a `FailureMemoryStore`; no
authorization or commit decision is affected by recurrence counts. A
caller — a CI gate, a dashboard, or an LLM explaining "this looks like a
recurring issue" — may consult `FailureMemorySummary`, but the store
itself never makes, blocks, or overrides a security decision.

### Surfaces

- Library: `FailureMemoryStore`, `FailureMemorySummary`,
  `failure_signature()`, `failure_signature_for()`
- CLI: `karmasakshi agenteval record <manifest_id> --failure-category CAT
  [--invariant STR]` (exports + records in one step, reports the new
  recurrence count), `karmasakshi agenteval history` (summarizes all
  recorded signatures)
- API: `POST /manifests/{id}/agenteval/fixtures` (authenticated),
  `GET /agenteval/fixtures/history` (authenticated)

### Known limitations

- **Unbounded by design.** Like an application log, the store never
  expires or truncates entries on its own — forgetting past failures
  would defeat the point of a memory. Callers who need rotation/archival
  manage the file themselves.
- **Signature is exact-match only.** Two failures that are conceptually
  similar but differ in `failure_category` string or which `invariant`
  was cited are treated as distinct shapes — there is no fuzzy matching
  or clustering.
- **Local file only.** No shared/remote store (database, object storage)
  ships in this phase; multiple processes writing to the same file
  concurrently are not coordinated beyond OS-level append semantics.
