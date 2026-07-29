# Separation of Duties

Status: **implemented** (extreme-v2 Phase 4). Package: `karmasakshi.duty`.

## What it is

Phase 3 already has *ad hoc* versions of protocol roles scattered through
`authorize_with_quorum()`'s parameters (`proposer`, `subject` (executor),
the set of approving principals) and two hard-coded self-approval rules
(`forbid_proposer_as_approver`, `forbid_subject_as_approver`). Phase 4
formalizes this into:

1. An explicit, closed set of protocol roles (`ProtocolRole`).
2. A structural record of which principal(s) held which role(s) for one
   manifest (`RoleAssignment`).
3. A versioned, signable forbidden-role-pair matrix
   (`SeparationOfDutyPolicy`), wrapped in the same signed `PolicyBundle`
   envelope Phase 2 introduced (`policy_type="separation.v1"`).
4. A pure, deterministic check (`check_separation_of_duty`) wired inline
   into `authorize()` and `authorize_with_quorum()` -- not a new gate
   that runs after them.

This is additive and fully opt-in, exactly like Phase 2's `policy_bundle`
and Phase 3's `approval_policy_bundle`: omitting
`separation_policy_bundle` leaves `authorize()`/`authorize_with_quorum()`
behaving exactly as before Phase 4 existed.

## Protocol roles (`karmasakshi/duty/roles.py`)

`ProtocolRole`: `proposer`, `resolver`, `assessor`, `sealer`, `approver`,
`executor`, `verifier`, `witness`, `compensator`, `auditor` -- named after
the protocol lifecycle stages (PROPOSE -> PREPARE -> ASSESS -> SEAL ->
AUTHORIZE -> COMMIT -> VERIFY) plus the cross-cutting compensator and
auditor roles.

`RoleAssignment(manifest_hash, assignments)`: a set of `(role,
principal_id)` facts for one exact manifest (identified by its canonical
hash, the same anchor `ApprovalStatement` and `ExecutionGrant` bind to).
A role may be held by more than one principal (e.g. several approvers
under quorum); a principal may hold more than one role. `RoleAssignment`
only records facts -- it does not judge whether holding multiple roles is
permitted, that's `check_separation_of_duty`'s job. Structurally bounded
(at most 256 entries, fail closed on overflow) and self-validating
(unknown role names, empty principal ids, and exact duplicate entries are
all rejected at construction).

`base_role_assignment(manifest_hash, *, proposer_id, executor_id,
approver_ids)` is the pure function the engine uses internally to derive
the role facts it already knows from an `authorize()` /
`authorize_with_quorum()` call's own parameters, before merging in any
caller-supplied additional roles via `RoleAssignment.merge()`. It is
exported so a caller building an Action Passport later can reconstruct
the identical base assignment from the same principals it already used
at authorization time.

## Separation-of-duty policy (`karmasakshi/duty/policy.py`)

`SeparationOfDutyPolicy`: `policy_id`, `policy_version`,
`forbidden_role_pairs` -- a set of unordered role-name pairs that may
never be held by the same principal for one manifest. The default matrix
is a conservative starting point: `sealer`-`approver`,
`proposer`-`approver`, `approver`-`executor`. A pair with itself (e.g.
`("approver", "approver")`) is rejected as meaningless, and duplicate
pairs (order-independent -- `("a", "b")` and `("b", "a")` are the same
pair) are rejected. Bounded at 64 pairs. Wrapped in a signed
`PolicyBundle` via `build_separation_of_duty_policy_bundle` /
`separation_of_duty_policy_from_bundle_payload`, exactly like
`IntelligencePolicy` and `ApprovalPolicy` -- an agent principal can never
be the issuer (invariant #30 applied identically, via the same
`PolicyBundleIssuerNotAuthorizedError`).

## Evaluation (`karmasakshi/duty/enforcement.py`)

`check_separation_of_duty(assignment, policy)` is a pure, deterministic,
order-independent function (property-tested --
`tests/property/test_separation_of_duty_properties.py`). For each
forbidden pair `(role_a, role_b)`, it computes the set intersection of
principals holding `role_a` and principals holding `role_b`; every
principal in that intersection is one violation. A principal holding
several conflicting roles at once produces one violation per offending
pair -- the check is structural (a set intersection), not a tally an
attacker can dilute by adding more compliant approvers alongside a
conflicted one (see
`tests/adversarial/test_separation_of_duty_gaming.py::test_one_conflicting_approver_among_several_still_blocks`).

## Binding into the engine

Both `KarmaSakshiEngine.authorize()` and `.authorize_with_quorum()` take
two new optional keyword arguments:

- `separation_policy_bundle: SealedPolicyBundle | None` -- when given, it
  is verified (signature, tamper, effective window, `policy_type ==
  "separation.v1"`) and the resulting `SeparationOfDutyPolicy` is checked
  against the combined role assignment. A violation raises
  `SeparationOfDutyViolationError` **before** `issue_grant()` is ever
  called -- the grant is structurally impossible to obtain when a
  violation exists, exactly like Phase 3's `QuorumNotMetError`.
- `role_assignment: RoleAssignment | None` -- additional role facts
  (e.g. who sealed, who witnessed) beyond what the engine can already
  derive automatically (proposer, executor, and approver(s)). Must be
  bound to the same manifest hash being authorized, or
  `RoleAssignmentError` is raised immediately (a mismatched
  `role_assignment` is rejected outright rather than silently ignored or
  silently applied to the wrong manifest).

In `authorize()`, the auto-derived roles are: `proposer` = the sealed
manifest's `actor`, `executor` = `subject`, `approver` = `issuer` (the
single authorizing principal). In `authorize_with_quorum()`: `proposer` =
`proposer`, `executor` = `subject`, `approver` = every principal
`evaluate_quorum()` actually counted (`QuorumResult.approving_principal_ids`
-- there may be more than one).

An audit event (`separation_of_duty.evaluated`) is recorded whenever a
`separation_policy_bundle` is checked, `satisfied` or `violated` either
way. Whether or not a bundle is bound, a successful `grant.issued` audit
event's metadata always carries the combined role assignment as
`role:<role>` keys (comma-joined principal ids per role) -- this is how
the Action Passport's `role_participation` field is populated (see
below), with no extra plumbing required from CLI/API callers.

### Why there is no re-verification at `commit()` time

Unlike `policy_bundle` (Phase 2), separation of duty has no persisted
hash on `ExecutionGrant` and nothing is re-checked at `commit()`. The
check is a one-time authorization-time gate over facts the engine itself
derives (or the caller explicitly asserts) at that moment -- there is no
separately-signed, swappable artifact analogous to a policy bundle to
protect against post-hoc substitution. This mirrors Phase 3's approval
set, which also is not re-verified at `commit()` for the same reason
(see docs/multi-party-authorization.md).

## Action Passport

`ActionPassport.role_participation: dict[str, str] | None` -- one entry
per role that appeared in the most recent `grant.issued` audit event for
the manifest, e.g. `{"proposer": "agent-1", "approver": "user-a,user-b",
"executor": "agent-1"}`. `None` if no grant was ever issued, or the grant
was issued by a pre-Phase-4 codepath. `passports.build_passport()` reads
this from the audit trail automatically; a caller can override it by
passing an explicit `role_assignment` if it wants the passport to reflect
a role assignment it built itself.

## CLI

```text
karmasakshi policy create-separation <bundle_id> --issuer-id ID
    [--forbidden-pair "role_a:role_b" ...]   # repeatable; default matrix if omitted
karmasakshi policy sign <bundle_id> --key-id ID       # reused, generic across bundle types
karmasakshi policy verify <bundle_id>                 # reused, generic across bundle types

karmasakshi grant issue <manifest_id> ... [--separation-policy-bundle-id ID]
    [--role "role_name:principal_id" ...]    # repeatable, additional roles
karmasakshi grant issue-with-quorum <manifest_id> ... [--separation-policy-bundle-id ID]
    [--role "role_name:principal_id" ...]
```

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/policy/separation-bundles` | Build, sign, store a separation-of-duty policy bundle |
| POST | `/manifests/{id}/approve` | `separation_policy_bundle_id` and `roles: ["role:principal_id", ...]` fields, optional |
| POST | `/manifests/{id}/approve-with-quorum` | Same two optional fields |

## Known limitations

- **Roles beyond proposer/executor/approver are entirely caller-supplied.**
  The engine has no way to independently verify that a principal
  asserted as `sealer` or `witness` actually performed that action --
  `role_assignment` is trusted caller input, the same trust level already
  extended to `issuer`/`subject`/`proposer` throughout this codebase.
  There is no cryptographic binding between, say, the key that actually
  signed a seal and a `sealer` role entry (a real production deployment
  wanting that guarantee would need to derive `sealer` from
  `Seal.key_id` via an external key-to-principal directory -- not
  implemented here).
- **No persisted binding on the grant.** Unlike `policy_bundle_hash` and
  `approval_set_hash`, there is no `ExecutionGrant` field recording that
  a separation check happened or which policy was used -- only the audit
  trail records it. A grant alone cannot prove after the fact that
  separation of duty was enforced at issuance; the audit journal must be
  consulted.
- **`ApprovalPolicy`'s own `forbid_proposer_as_approver`/
  `forbid_subject_as_approver` (Phase 3) are untouched and run
  independently.** A caller wanting both Phase 3's quorum-specific
  self-approval rejection and Phase 4's general matrix runs both checks
  (they compose; neither supersedes the other).
