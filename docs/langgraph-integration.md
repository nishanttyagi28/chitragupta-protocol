# LangGraph Integration

`chitragupta.integrations.langgraph` (optional: `pip install
chitragupta-protocol[langgraph]`) demonstrates pausing a LangGraph run for
human authorization and resuming through the real engine. The core engine
has zero import-time dependency on LangGraph — importing
`chitragupta.integrations.langgraph` without the extra installed raises a
clear `ImportError` naming it, and nothing in `chitragupta.engine` imports
this module.

## The graph

```python
from chitragupta.integrations.langgraph import build_chitragupta_graph

app = build_chitragupta_graph(engine=engine, adapter=adapter, signing_key=signing_key)
```

Four nodes: `prepare -> seal -> authorize -> commit`. `authorize` calls
LangGraph's `interrupt()` with the sealed manifest and its hash, pausing
the graph. Resume with:

```python
from langgraph.types import Command

result = app.invoke({"request": my_request}, config=config)
# result["status"] == "sealed"; graph is paused at "authorize"

resumed = app.invoke(
    Command(
        resume={
            "approved": True,
            "issuer": {"principal_id": "approver-1", "principal_type": "human"},
            "subject": {"principal_id": "agent-1", "principal_type": "agent"},
        }
    ),
    config=config,
)
# resumed["status"] == "verified"
```

Denial: `Command(resume={"approved": False, "reason": "..."})` — the graph
records `status="denied"` and never calls `engine.authorize()` at all.

## Why the signing key never reaches the agent or the checkpoint

`build_chitragupta_graph()` captures `signing_key` in the *builder's*
closure — it is never placed into `ChitraguptaGraphState`, so it can never
be serialized into a LangGraph checkpoint (which persists whatever's in
state) and is never visible to whatever code produced the agent's
`request`. This is verified directly:
`test_interrupt_payload_never_contains_signing_material` asserts the
interrupt payload handed to the human/service reviewer contains no
`"signature"`, `"private"`, or PEM-looking (`"BEGIN"`) content.

## Invariant #30 still applies

Even though the graph is the one deciding to call `engine.authorize()`
after a `Command(resume=...)`, the engine itself still enforces that
`issuer.principal_type` is not `agent` — `test_agent_cannot_be_the_authorizing_issuer`
resumes a paused run with an agent-typed issuer and confirms
`status == "authorization_failed"`. The graph gives you a place to plug in
a human-in-the-loop step; it doesn't (and can't) bypass the engine's own
authorization rule.

## Denied / expired / stale / tampered cases

- **Denied**: `status="denied"`, no grant ever issued
  (`test_denied_authorization_never_commits`).
- **Expired**: resuming with an already-past `expires_at` reaches
  `authorize` successfully (the grant *is* issued — it's a valid signed
  object) but `commit` then fails with `status="commit_failed"` because
  `engine.commit()` re-verifies the time window
  (`test_already_expired_authorization_window_fails_at_commit`).
- **Revoked / stale / tampered**: these are core-engine behaviors
  (invariants #7, #14, #3/#11) that apply identically regardless of which
  framework is driving the engine — see `docs/security-model.md` and the
  demo suite (scenarios 3, 5, 8, 10) rather than LangGraph-specific tests,
  since the engine's `commit()` doesn't know or care whether it was called
  from a LangGraph node, the CLI, or the API.

## What's demonstrated vs. what's not

Demonstrated: pause-for-approval, resume, deny, agent-cannot-self-authorize,
expired-grant-fails-at-commit, no-secrets-in-checkpoint. Not built: a
production-grade human-approval UI (the FastAPI console in
`chitragupta.web` is a separate, standalone control plane, not wired to
this LangGraph integration), or persistence of LangGraph checkpoints
beyond the default in-memory `MemorySaver` (a real deployment would supply
its own `BaseCheckpointSaver`, e.g. backed by Postgres — LangGraph's
concern, not this integration's).
