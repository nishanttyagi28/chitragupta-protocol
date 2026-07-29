# CLI Reference

`karmasakshi [--workspace PATH] [--json] <command> ...`

`--workspace` defaults to `.karmasakshi` under the current directory (or
`$KARMASAKSHI_HOME`). `--json` switches every command to machine-readable
JSON output. Exit codes: `0` success, `1` general/validation error, `2`
security-denied (any `KarmaSakshiError` subclass).

## Workspace

The workspace holds dev keys (`keys/`), sealed manifests and their commit/
verify/compensation results (`manifests/`), grants (`grants/`), a
SQLite-backed grant store (`grants.db`), and a SQLite-backed audit journal
(`audit.db`) — everything needed to run `prepare`, `seal`, `grant issue`,
`execute`, `verify`, `compensate`, `passport`, and `audit` as *separate*
process invocations while keeping a consistent lifecycle state. See
`karmasakshi.cli.workspace.Workspace.reconstruct_lifecycle_state()` and
[docs/state-machine.md](state-machine.md) for how that consistency is
maintained across processes.

## Commands

```text
karmasakshi init
karmasakshi key generate <key_id>
karmasakshi key list

karmasakshi prepare --adapter {sqlite,email,payment} --actor-id ID [adapter-specific options...]
karmasakshi assess <manifest_id> [--delegation-depth N] [--historical-recurrence-count N]
    [--historical-failure-count N] [--provider-idempotent unknown|yes|no]
    [--compensation-feasible unknown|yes|no] [--cross-tenant] [--unusual-parameter-change]
    [--policy-violation TEXT ...] [--from-audit-history]
karmasakshi seal <manifest_id> --key-id ID

karmasakshi grant issue <manifest_id> --issuer-id ID --subject-id ID --key-id ID [--audience ...] [--max-uses N]
karmasakshi grant verify <grant_id>
karmasakshi grant delegate <parent_grant_id> --issuer-id ID --subject-id ID --key-id ID [--max-uses N] [--ttl-seconds N]
karmasakshi grant revoke <grant_id> [--manifest-id ID]
karmasakshi grant inspect <grant_id>

karmasakshi execute <manifest_id> --grant-id ID --adapter {sqlite,email,payment} [adapter-specific options...]
karmasakshi verify <manifest_id> --adapter {sqlite,email,payment} [...]
karmasakshi compensate <manifest_id> --adapter {sqlite,email,payment} [...]

karmasakshi audit list
karmasakshi audit show <manifest_id>
karmasakshi audit verify

karmasakshi passport <manifest_id> [--format json|markdown|html] [--grant-id ID] [-o FILE]

karmasakshi demo --all
karmasakshi doctor
karmasakshi version
```

## Adapter-specific `prepare`/`execute`/`verify`/`compensate` options

Only the three reference adapters are wired into the CLI (`sqlite`,
`email`, `payment`) — this is deliberate: the CLI resolves `--adapter` to a
concrete class, never dynamically imports/executes arbitrary adapter code
from a string, to avoid an arbitrary-code-loading surface in a
security-focused tool. Third-party adapters are used via the Python API.

- `--adapter sqlite`: `--sqlite-db-path PATH` (required), `--sqlite-table
  NAME`, `--row-operation {insert,update,delete}`, `--row-id ID`,
  `--new-balance N`.
- `--adapter email`: `--recipient EMAIL` (repeatable), `--subject TEXT`,
  `--body TEXT`.
- `--adapter payment`: `--source-account ID`, `--beneficiary ID`,
  `--amount-minor-units N`, `--currency CODE`, `--reference TEXT`,
  `--fee-minor-units N`, `--fund-source-account N` (pre-funds the account
  before the effect, for one-shot local testing).

**Important limitation:** the `email` and `payment` adapters hold state in
memory only. A fresh CLI process starts them from empty (zero balance,
empty outbox) — there is no cross-process persistence for these two
reference adapters (only `sqlite` persists naturally, via its own database
file). Use `karmasakshi demo --all` to see a full single-process
walkthrough of all three, or drive the Python API directly for real
multi-step usage against the in-memory adapters.

## `assess`

Runs the deterministic Effect Intelligence Engine over a prepared (sealed
or unsealed) manifest and records an `effect.assessed` audit event. Does
not require the manifest to be sealed first, and does not transition the
lifecycle state. **Advisory only** — the recommendation is not read or
enforced by `grant issue`/`execute`. See
[docs/effect-intelligence.md](effect-intelligence.md). `--from-audit-history`
derives the recurrence/failure facts from this workspace's own audit
journal instead of the `--historical-*` flags.

## `doctor`

Checks workspace initialization, key availability (counts and ids only —
never key material), grant store reachability, audit chain integrity,
clock timezone-awareness, and adapter registration. Exits non-zero if any
check fails.

## `demo --all`

Runs all 15 required scenarios deterministically, self-contained (its own
in-memory engine, its own signing keys, its own temp-file SQLite adapter)
— does not touch `--workspace`. See the README for exact output from a
real run.
