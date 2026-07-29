# Writing an Effect Adapter

An adapter implements `karmasakshi.adapters.base.EffectAdapter` (sync) or
`AsyncEffectAdapter` (async — same method names, coroutines). The engine
calls these five methods and makes every authorization decision itself;
**adapters never decide authorization**.

```python
class EffectAdapter(Protocol):
    adapter_id: str
    adapter_version: str

    def prepare(self, request, context) -> EffectManifest: ...
    def validate_preconditions(self, manifest, context) -> PreconditionResult: ...
    def commit(self, manifest, grant, context) -> CommitResult: ...
    def verify(self, manifest, commit_result, context) -> OutcomeProof: ...
    def compensate(self, manifest, commit_result, context) -> CompensationResult: ...
```

## `prepare(request, context) -> EffectManifest`

Resolve `request` (your own adapter-specific type — see
`RowEffectRequest`, `EmailRequest`, `PaymentRequest` for examples) into a
fully-populated `EffectManifest`. This is where you:

- Capture a `StateFingerprint` precondition (row version, ETag, provider
  balance snapshot — whatever lets `validate_preconditions()` later detect
  that external state changed).
- Classify `risk`, `reversibility`, `blast_radius` honestly — never
  `IRREVERSIBLE` effects as `COMPENSATABLE`, never mark something
  reversible just because a naive undo is *possible* (see
  `SQLiteRowAdapter`'s decision to treat `delete` as irreversible even
  though a snapshot-based undo is technically feasible).
- Normalize parameters into the flat `str | int | bool | None` shape.

## `validate_preconditions(manifest, context) -> PreconditionResult`

Called by the engine immediately before `commit()` — this is the TOCTOU
check. Re-read the actual current state and compare it to
`manifest.state_fingerprint`. Return `PreconditionResult(satisfied=False,
reason=..., observed_fingerprint=...)` on any mismatch; the engine turns
this into `StaleManifestError` and releases the grant reservation without
consuming a use.

## `commit(manifest, grant, context) -> CommitResult`

Perform the actual external effect, using **parameterized operations
only** — never construct a query/command from unvalidated manifest
parameters via string interpolation of user/agent-controlled values (see
`SQLiteRowAdapter`'s use of `?` placeholders throughout; table *names* are
fixed constructor-time configuration, never derived from the manifest,
which is why that's safe to interpolate while values never are).

Use `manifest.idempotency_key` as your own provider-side idempotency key
where the underlying system supports one (see `PaymentSimulator`'s
`provider_idempotency_key` — this gives you a second layer of duplicate
protection independent of the engine's own idempotency ledger). Return
`CommitResult(success=False, ...)` for an honest failure; don't raise for
expected failure modes — reserve exceptions for genuine adapter bugs.

## `verify(manifest, commit_result, context) -> OutcomeProof`

**Never trust `commit_result` alone.** Re-read your own external system of
record independently — a database row, a sandbox outbox, a provider's own
ledger — and compare it to what the manifest expected. This is what makes
invariant #20/#21 real rather than aspirational; see every reference
adapter's `verify()` implementation for the pattern.

## `compensate(manifest, commit_result, context) -> CompensationResult`

Best-effort only. Return `CompensationResult(attempted=False, succeeded=False,
reason="...")` — honestly — for anything genuinely irreversible (see the
email adapter: always refuses, since a sent email cannot be recalled) or
for provider states that don't support cancellation (see the payment
simulator: a *settled* transfer cannot be reversed by this simulator, only
a real reversing payment could attempt it, and that's not guaranteed to
succeed either). Never report `succeeded=True` unless you have positive
confirmation the compensating action took effect.

## Registering with the engine

Adapters are plain objects passed explicitly to `engine.prepare()` /
`engine.commit()` / etc. There is **no dynamic plugin discovery**.

When `EngineContext.adapter_registry` is configured (extreme-v2 Phase 17),
the engine additionally fails closed unless the adapter's exact
`(adapter_id, adapter_version)` is on the trusted allow-list and the
manifest's `effect_type` is declared in that capability. See
[docs/trusted-adapter-registry.md](trusted-adapter-registry.md).

The CLI's `adapter_factory.py` and the API's `ApiState.adapters` dict are
examples of *callers* wiring up adapters; the API default state also
installs `build_reference_registry()`.

## Conformance kit

Third-party adapters should run
[`run_adapter_conformance`](adapter-conformance.md) (extreme-v2 Phase 18)
against a representative request before claiming compatibility. The kit
checks identity binding, TOCTOU-shaped precondition behaviour, independent
verification (forged success before commit must not match), and honest
compensation reporting. Passing is **not** a cloud-provider certification.
