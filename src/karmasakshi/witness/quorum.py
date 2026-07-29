"""Deterministic independent witness quorum evaluation."""

from __future__ import annotations

from datetime import datetime

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import KarmaSakshiError, WitnessBatchTooLargeError
from karmasakshi.witness.model import WitnessPolicy, WitnessQuorumResult, WitnessStatement
from karmasakshi.witness.signing import (
    verify_witness_statement_signature,
    verify_witness_statement_time_window,
)


def evaluate_witness_quorum(
    statements: tuple[WitnessStatement, ...] | list[WitnessStatement],
    policy: WitnessPolicy,
    *,
    manifest_hash: str,
    expected_after_state_digest: str,
    actor: Principal,
    subject: Principal,
    keyring: Keyring,
    now: datetime,
) -> WitnessQuorumResult:
    """Evaluate witness quorum. Pure and order-independent.

    Fail-closed: oversized batches raise; agents, actor/subject (when
    forbidden), digest/policy mismatches, expired or invalid signatures
    never count toward quorum.
    """
    policy_hash = policy.policy_hash()
    if len(statements) > policy.max_statements_considered:
        raise WitnessBatchTooLargeError(
            f"received {len(statements)} witness statements; "
            f"max_statements_considered={policy.max_statements_considered}"
        )

    rejections: list[str] = []
    survivors: list[WitnessStatement] = []
    for stmt in statements:
        reason = _reject_reason(
            stmt,
            manifest_hash=manifest_hash,
            policy_hash=policy_hash,
            expected_after_state_digest=expected_after_state_digest,
            policy=policy,
            actor=actor,
            subject=subject,
            keyring=keyring,
            now=now,
        )
        if reason is None:
            survivors.append(stmt)
        else:
            rejections.append(f"{stmt.statement_id}:{reason}")

    by_witness: dict[str, list[WitnessStatement]] = {}
    for stmt in survivors:
        by_witness.setdefault(stmt.witness.principal_id, []).append(stmt)

    authoritative: list[WitnessStatement] = []
    for group in by_witness.values():
        winner = max(group, key=lambda s: (s.signed_at, s.statement_id))
        authoritative.append(winner)

    authoritative.sort(key=lambda s: s.witness.principal_id)
    accepted_ids = tuple(s.witness.principal_id for s in authoritative)
    satisfied = len(authoritative) >= policy.required_witnesses
    witness_set_hash = None
    if satisfied:
        witness_set_hash = canonical_hash(
            {
                "manifest_hash": manifest_hash,
                "witness_policy_hash": policy_hash,
                "digest": expected_after_state_digest,
                "witnesses": list(accepted_ids),
            }
        )
    return WitnessQuorumResult(
        satisfied=satisfied,
        witness_policy_hash=policy_hash,
        witness_set_hash=witness_set_hash,
        accepted_witness_ids=accepted_ids,
        rejection_reasons=tuple(sorted(rejections)),
    )


def _reject_reason(
    statement: WitnessStatement,
    *,
    manifest_hash: str,
    policy_hash: str,
    expected_after_state_digest: str,
    policy: WitnessPolicy,
    actor: Principal,
    subject: Principal,
    keyring: Keyring,
    now: datetime,
) -> str | None:
    if statement.manifest_hash != manifest_hash:
        return "manifest_hash mismatch"
    if statement.witness_policy_hash != policy_hash:
        return "witness_policy_hash mismatch"
    if statement.observed_after_state_digest != expected_after_state_digest:
        return "observed_after_state_digest mismatch"
    if policy.require_matched_expected and not statement.matched_expected:
        return "matched_expected must be true"
    if statement.witness.principal_type == PrincipalType.AGENT:
        return "agent principals cannot witness"
    if policy.forbid_actor_as_witness and statement.witness.principal_id == actor.principal_id:
        return "actor cannot witness its own effect"
    if policy.forbid_subject_as_witness and statement.witness.principal_id == subject.principal_id:
        return "subject/executor cannot witness its own effect"
    try:
        verify_witness_statement_signature(statement, keyring)
        verify_witness_statement_time_window(statement, now)
    except KarmaSakshiError as exc:
        return str(exc)
    return None


__all__ = ["evaluate_witness_quorum"]
