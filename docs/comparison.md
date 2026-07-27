# Comparison

This document sticks to what can be verified from each project's own
stated purpose. It does not claim to have benchmarked, audited, or
exhaustively tested any other project's implementation.

## Category distinction: evaluation vs. runtime authorization

```text
AgentEval:
  Did the agent behave correctly during development and CI?

Chitragupta Protocol:
  Did the exact approved real-world effect match the actual outcome?
```

AgentEval-style tooling evaluates agent behavior against test cases,
typically offline or in CI, before or after the fact. Chitragupta Protocol
operates at runtime, on individual consequential actions: it stages an
exact effect, seals it, requires a non-agent principal to authorize that
exact sealed effect, executes it, and independently verifies the outcome.
These are complementary rather than competing — a production failure
caught by Chitragupta Protocol's verification step can be exported
(`chitragupta.integrations.agenteval`) as a regression fixture for
AgentEval-style offline evaluation to catch going forward. See
[docs/agenteval-integration.md](agenteval-integration.md) for the honest
caveat that the exact AgentEval fixture schema was not confirmed, so this
export is a neutral, versioned format rather than a claimed-compatible one.

## Comparison to generic tool-permission layers

Many agent frameworks implement authorization as "may this agent call
this named tool" (optionally with a JSON-schema-validated argument shape).
That is a real and useful control, but it authorizes the *capability*, not
the *exact resolved effect*. Chitragupta Protocol's manifest/grant binding
is a stricter, narrower claim: a grant is valid for one specific,
canonically-hashed effect (target, amount, parameters, preconditions),
not for "any call matching this tool's schema." The two approaches are not
mutually exclusive — a tool-permission layer can sit in front of
Chitragupta Protocol's `prepare()` step to decide which tools an agent may
even attempt to resolve into a manifest.

## What this document does not do

It does not name or rank specific commercial or open-source competitors,
because doing so accurately would require verifying their current feature
set and implementation quality first-hand, which is outside this project's
scope. If you are evaluating Chitragupta Protocol against another specific
tool, the questions worth asking are:

1. Does authorization bind to the exact resolved effect (target, amount,
   parameters, preconditions), or to a tool name / capability?
2. Is there independent, post-execution verification of the actual
   outcome, or does the system trust the tool call's return value?
3. Is there TOCTOU protection — does authorization survive external state
   changing between approval and execution, or does it silently execute
   against whatever state exists at call time?
4. Can a sub-agent widen its own authority through delegation, or is
   narrowing enforced and tested?
5. Is the audit trail tamper-evident, or just a log?

Chitragupta Protocol's answers to all five are implemented and tested —
see [docs/security-model.md](security-model.md) for exactly where.
