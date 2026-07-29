# Multi-Party (M-of-N) Authorization

Status: **implemented** (extreme-v2 Phase 3). Package: `karmasakshi.approval`.

## What it is

`engine.authorize()` (single-issuer) remains fully supported and
unchanged. `engine.authorize_with_quorum()` is an additive entry point
that issues an `ExecutionGrant` only if a set of signed
`ApprovalStatement`s satisfies a versioned, signed `ApprovalPolicy`
(quorum rules) bound in a `PolicyBundle` (the same envelope Phase 2
introduced, `policy_type="approval.v1"`).

## Domain model (`karmasakshi/approval/model.py`)

- **`ApprovalStatement`**: one principal's signed decision
  (`approve`/`dissent`) on one exact `(manifest_hash,
  approval_policy_bundle_hash)` pair, with an explicit `role` (optional,
  self-asserted -- see Known Limitations), `reason` (optional, for
  dissent), `signed_at`, and `expires_at`. Structurally identical to
  `ExecutionGrant` -- self-signing, `canonical_hash()` covers every field
  except `signature`.
- **`QuorumResult`**: the outcome of evaluating a statement set --
  `satisfied`, `approving_count`, `approving_principal_ids`,
  `dissenting_principal_ids`, `missing_roles`, `rejected` (per-statement
  reasons), `reason` (a deterministic explanation), `approval_set_hash`.

## Quorum rules (`karmasakshi/approval/policy.py`)

`ApprovalPolicy`: `required_approvals`, `required_roles` (each must be
represented by at least one approving statement), `forbid_proposer_as_approver`
(default `True`), `forbid_subject_as_approver` (default `True`),
`veto_on_any_dissent` (default `True`), `cooling_off_seconds` (delays
satisfaction until this long after the earliest counted approval),
`max_statements_considered` (resource bound -- see below). Like
`IntelligencePolicy`, wrapped in a signed `PolicyBundle` via
`build_approval_policy_bundle`/`approval_policy_from_bundle_payload`.

## Evaluation (`karmasakshi/approval/quorum.py`)

`evaluate_quorum(statements, policy, *, manifest_hash,
approval_policy_bundle_hash, keyring, proposer, subject, now)` is a pure,
deterministic, **order-independent** function (property-tested --
`tests/property/test_approval_quorum_properties.py`). For each statement:

1. **Structural checks** (manifest/bundle mismatch, agent-typed approver,
   proposer/subject exclusion) reject immediately with a specific reason.
2. **Signature and time-window verification** (reuses `Keyring.verify` --
   unknown keys and forged signatures fail closed).
3. **Freshness tie-break**: statements are grouped by approver identity,
   and only the statement with the latest `signed_at` (ties broken by
   `statement_id`) is authoritative per approver -- so an approver who
   later dissents (or re-approves) has their most recent decision count,
   regardless of the order statements were collected or submitted. This
   is what makes the result identical no matter what order the caller
   passes statements in, even when one approver submitted conflicting
   statements (see `tests/adversarial/test_approval_gaming.py`).
4. Required-role coverage, dissent veto, and cooling-off are evaluated
   over the surviving, deduplicated set.

`QuorumResult.approval_set_hash` is a canonical hash over the sorted
canonical hashes of the *counted* approving statements -- deterministic
and tamper-evident (any change to a counted statement changes the hash).

Individual bad statements never raise -- they're recorded in
`QuorumResult.rejected` and evaluation continues. Submitting **more**
statements than `policy.max_statements_considered` allows raises
`ApprovalBatchTooLargeError` for the whole call (fail closed rather than
silently truncating, which could drop a statement that would have
changed the outcome).

## Binding into the engine

`KarmaSakshiEngine.authorize_with_quorum(sealed, *, statements,
approval_policy_bundle, proposer, subject, grant_issuer, ...)`:

1. Verifies `approval_policy_bundle` (signature, tamper, effective
   window, `policy_type == "approval.v1"`).
2. Evaluates quorum; records an `approval.quorum_evaluated` audit event
   either way (satisfied or not).
3. Raises `QuorumNotMetError` if not satisfied -- **the grant is
   structurally impossible to obtain any other way through this
   method**: there is no code path that produces a signed
   `ExecutionGrant` with `approval_set_hash` set except by a successful
   quorum evaluation immediately beforehand.
4. If satisfied, binds `QuorumResult.approval_set_hash` into
   `ExecutionGrant.approval_set_hash` (optional field, default `None`,
   fully backward compatible with `authorize()`-issued grants) and signs
   the grant as usual. `policy_bundle` (the Phase 2 Effect Intelligence
   policy bundle) can also be bound in the same call, independently.

### Why `commit()` does *not* re-verify the approval set

Unlike a Phase 2 `policy_bundle` (which `commit()` *does* require to be
re-presented and re-verified, because a policy is a living, re-editable
document an attacker could swap), each `ApprovalStatement` is already an
individually signed, immutable historical record, validated once at
`authorize_with_quorum()` time. There is nothing to "swap" post-hoc: the
statements themselves cannot be edited without invalidating their
signatures, and the grant's own signature already covers
`approval_set_hash`. Re-verifying the full statement set at every
`commit()` would also require the caller to keep transmitting
potentially-sensitive approver data indefinitely, for no additional
security benefit. See
`tests/unit/test_engine.py::test_authorize_with_quorum_grant_commits_without_re_presenting_approvals`.

## CLI

```text
karmasakshi policy create-approval <bundle_id> --issuer-id ID [--required-approvals N]
    [--required-role TEXT ...] [--forbid-proposer-as-approver/--no-forbid-proposer-as-approver]
    [--forbid-subject-as-approver/--no-forbid-subject-as-approver]
    [--veto-on-any-dissent/--no-veto-on-any-dissent] [--cooling-off-seconds N]
karmasakshi policy sign <bundle_id> --key-id ID       # reused, generic across bundle types
karmasakshi policy verify <bundle_id>                 # reused, generic across bundle types

karmasakshi approve <manifest_id> --approver-id ID --key-id ID --approval-policy-bundle-id ID
    [--approver-type human|service] [--role TEXT] [--decision approve|dissent] [--reason TEXT]

karmasakshi approvals inspect <manifest_id> --approval-policy-bundle-id ID
    --proposer-id ID --subject-id ID    # dry run, does not issue a grant

karmasakshi grant issue-with-quorum <manifest_id> --approval-policy-bundle-id ID
    --grant-issuer-id ID --proposer-id ID --subject-id ID --key-id ID
    [--audience ...] [--policy-bundle-id ID]
```

Each CLI-signed approval statement uses a genuinely distinct local
signing key per approver (one dev key per identity, exactly like the
Phase 2 policy-bundle workflow) -- see the API section below for an
important difference in the reference control plane.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/policy/approval-bundles` | Build, sign, store an approval policy bundle |
| POST | `/manifests/{id}/approvals` | Record one approval/dissent statement |
| GET | `/manifests/{id}/approvals` | List statements recorded for a manifest |
| POST | `/manifests/{id}/approvals/evaluate` | Dry-run quorum evaluation |
| POST | `/manifests/{id}/approve-with-quorum` | Issue a grant if quorum is met (`403` if not) |

**Honesty note:** the reference control plane signs every
API-submitted approval statement with its own single service signing
key (`ApiState.signing_key`) -- the same key already used for manifests,
grants, and policy bundles elsewhere in this API. It does **not** hold a
distinct private key per human approver. The `approver` identity is
still recorded and every quorum rule (duplicate/self/subject-approver
rejection, role requirements) still applies in full, but the
cryptographic signature alone does not, in this reference deployment,
prove which physical human submitted a given API call the way
independently-held keys would in production. The CLI does not have this
limitation (each workspace key is a genuinely separate keypair). A
production deployment would issue each approver their own key via an
external signer (a documented gap -- see Phase 16 in the build ledger)
and have the API verify a client-signed submission rather than sign on
the approver's behalf.

## Known limitations

- **Roles are self-asserted.** `ApprovalStatement.role` is part of the
  signed payload (so it cannot be tampered with post-signature), but
  nothing checks it against an external identity/role directory --
  Phase 3 has no RBAC system yet (see Phase 4, separation of duties, and
  the commercial roadmap's enterprise "approval groups").
- **API approval signatures share one service key** -- see above.
- **No re-verification of the approval set at commit time** -- by
  design, see "Why `commit()` does not re-verify" above; documented so
  this isn't mistaken for an oversight.
- **`EffectAssessment.required_human_approvals` (Phase 1) is not yet
  wired to automatically set `ApprovalPolicy.required_approvals`.** The
  two systems compose (nothing prevents a caller from reading one and
  configuring the other), but there is no automatic enforcement link yet.
