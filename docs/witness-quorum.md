"""Independent witness quorum (extreme-v2 Phase 9).

Witnesses are **not** approvers. Approvals authorize an effect before
COMMIT. Witnesses attest to what was independently observed *after*
COMMIT/VERIFY, so PROVE-time acceptance of critical effects can require
N distinct human/service observers.

## Concepts

- ``WitnessStatement`` — signed observation of ``observed_after_state_digest``
  and ``matched_expected``, bound to one ``manifest_hash`` and one
  ``witness_policy_hash``.
- ``WitnessPolicy`` — required witness count, forbid actor/subject as
  witnesses, require matched_expected, max batch size.
- ``evaluate_witness_quorum`` — pure, order-independent; agents never count.
- ``KarmaSakshiEngine.prove_with_witness_quorum`` — assert path used at
  PROVE time (passport / evidence acceptance). Does not add a new
  lifecycle state (PROVE remains the Action Passport surface).

## Invariants

- **#50** Agents cannot sign or satisfy witness quorum.
- **#51** Actor and subject/executor cannot witness their own effect when
  the policy forbids it (default).
- **#52** Digest / policy-hash / expiry / signature failures fail closed
  and never count toward quorum; oversized batches raise.
- **#53** Quorum evaluation is deterministic and order-independent; the
  same authoritative witness set always yields the same
  ``witness_set_hash``.

## CLI / API

- ``karmasakshi witness sign|evaluate``
- ``POST/GET /manifests/{id}/witnesses``, ``POST .../witnesses/evaluate``

## Honesty limits

- Sealed ``witness.v1`` policy bundles (hash-pinned like approval.v1) are
  deferred; statements already bind ``witness_policy_hash`` of the plain
  ``WitnessPolicy`` used at signing time.
- Multi-node durable witness collection stores are Phase 13+.
- Reference API signs with the control-plane service key (same honesty
  note as approvals); use the CLI with distinct keys for real separation.
"""
