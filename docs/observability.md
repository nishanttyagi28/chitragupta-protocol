# Observability

Extreme-v2 **Phase 24** introduces `karmasakshi.observability`: a neutral,
versioned lifecycle event (`ObservabilityEvent`, schema `1.0`) and a small
set of pluggable sinks for forwarding it to external log/metrics systems.

## Honest scope statement

**This is not an integration with any named observability product.** No
OpenTelemetry, Datadog, Honeycomb, or Prometheus client is used or
implied. It defines one stable, documented JSON event shape a real
exporter could sit on top of later — the same honest boundary already
established for the AgentEval regression-fixture export
(see [docs/agenteval-integration.md](agenteval-integration.md)): a
self-describing, versioned document, not a claim of compatibility with
any specific upstream schema.

## Advisory only, like the Effect Intelligence Engine

Observability never gates any lifecycle transition and never affects any
security decision:

- `EngineContext.observability_sink` is optional (`None` by default).
- `KarmaSakshiEngine.observe(event_type, manifest_id, ...)` builds an
  `ObservabilityEvent` and forwards it to the configured sink, mirroring
  how `assess()` (Phase 1) is an explicit, audited-but-non-gating call
  rather than something automatically wired into `authorize()`/`commit()`.
  Unlike `assess()`, `observe()` events are **not** written to the
  tamper-evident audit journal — they are a separate, best-effort side
  channel for external consumption, not part of the protocol's own
  evidentiary record.
- A failing, slow, or buggy sink can never block, fail, or alter the
  outcome of a lifecycle call: `emit_safely()` swallows every sink
  exception and logs it instead of propagating.

Callers (CLI/API) invoke `engine.observe(...)` explicitly at whatever
lifecycle points matter to them — there is no automatic wiring into
`prepare()`/`authorize()`/`commit()`/`verify()`.

## Usage

```python
from karmasakshi.observability import InMemoryObservabilitySink, ObservabilityEventType

sink = InMemoryObservabilitySink()  # or JsonlObservabilitySink("events.jsonl")
engine.context.observability_sink = sink

event = engine.observe(
    ObservabilityEventType.EFFECT_COMMITTED,
    manifest.manifest_id,
    manifest_hash=sealed.seal.manifest_hash,
    grant_id=grant.grant_id,
    decision=commit_result.detail,
)
```

## Event shape

| Field | Content |
|---|---|
| `schema_version` | Always `"1.0"` |
| `event_type` | One of `manifest.prepared`, `grant.authorized`, `effect.committed`, `effect.verified`, `effect.compensated`, `lifecycle.failed` |
| `emitted_at` | UTC timestamp |
| `manifest_id`, `manifest_hash`, `grant_id` | Identifiers, optional where not yet known |
| `lifecycle_state` | The engine's current view at the moment of the call |
| `decision`, `detail` | Caller-supplied classification / free text (bounded to 2048 chars) |
| `tenant_id` | Carried from `EngineContext.tenant_id` when set (Phase 19) |

Never carries secrets, private keys, or raw credentials — only
identifiers and classification already present in the audit trail.

## Sinks

- `NullObservabilitySink` — discards everything (no-op default behavior
  when no sink is configured; `engine.observe()` also no-ops safely with
  `observability_sink=None`).
- `InMemoryObservabilitySink` — collects events in a list, for tests and
  local inspection.
- `JsonlObservabilitySink` — appends one JSON object per line to a local
  file: portable, tail-able, grep-able. Not a claim of integration with
  any specific log-shipping product.
- Callers may supply any object implementing `emit(event) -> None`
  (`ObservabilitySink` is a `Protocol`) to forward events elsewhere.

## Known limitations

- No remote/network sink ships in this phase (no HTTP, gRPC, or message
  queue exporter) — `JsonlObservabilitySink` is local-file only.
- Delivery is best-effort and unordered across concurrent callers beyond
  what the sink itself guarantees; `InMemoryObservabilitySink` and
  `JsonlObservabilitySink` are lock-protected for thread safety within one
  process, not across processes.
- Not wired automatically into every lifecycle method — see "Advisory
  only" above.
