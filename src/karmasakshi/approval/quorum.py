"""Deterministic, order-independent quorum evaluation.

``evaluate_quorum`` is a pure function of its inputs: given the same
statement set, policy, manifest hash, approval-policy-bundle hash,
proposer, subject, and evaluation time, it always returns the same
``QuorumResult`` -- regardless of the order the statements were
collected or passed in. See docs/multi-party-authorization.md.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from karmasakshi.approval.model import ApprovalStatement, QuorumResult
from karmasakshi.approval.policy import ApprovalPolicy
from karmasakshi.approval.signing import (
    verify_approval_statement_signature,
    verify_approval_statement_time_window,
)
from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import ApprovalBatchTooLargeError, KarmaSakshiError


def _reject_reason(
    statement: ApprovalStatement,
    *,
    manifest_hash: str,
    approval_policy_bundle_hash: str,
    policy: ApprovalPolicy,
    proposer: Principal,
    subject: Principal,
    keyring: Keyring,
    now: datetime,
) -> str | None:
    if statement.manifest_hash != manifest_hash:
        return "manifest_hash mismatch"
    if statement.approval_policy_bundle_hash != approval_policy_bundle_hash:
        return "approval_policy_bundle_hash mismatch"
    if statement.approver.principal_type == PrincipalType.AGENT:
        return "agent principals cannot approve (invariant #30)"
    if (
        policy.forbid_proposer_as_approver
        and statement.approver.principal_id == proposer.principal_id
    ):
        return "proposer cannot approve its own proposal"
    if (
        policy.forbid_subject_as_approver
        and statement.approver.principal_id == subject.principal_id
    ):
        return "subject/executor cannot satisfy approval quorum"
    try:
        verify_approval_statement_signature(statement, keyring)
        verify_approval_statement_time_window(statement, now)
    except KarmaSakshiError as exc:
        return str(exc)
    return None


def _select_authoritative(
    statements: list[ApprovalStatement],
) -> tuple[dict[str, ApprovalStatement], list[tuple[str, str]]]:
    """Group survivors by approver, keeping only the most recent statement
    per approver (ties broken by ``statement_id``) so the result is
    identical regardless of input order, even when one approver submitted
    conflicting statements."""
    by_approver: dict[str, list[ApprovalStatement]] = {}
    for stmt in statements:
        by_approver.setdefault(stmt.approver.principal_id, []).append(stmt)

    authoritative: dict[str, ApprovalStatement] = {}
    superseded: list[tuple[str, str]] = []
    for principal_id, group in by_approver.items():
        winner = max(group, key=lambda s: (s.signed_at, s.statement_id))
        authoritative[principal_id] = winner
        for stmt in group:
            if stmt.statement_id != winner.statement_id:
                superseded.append(
                    (stmt.statement_id, "superseded by a later statement from the same approver")
                )
    return authoritative, superseded


def evaluate_quorum(
    statements: tuple[ApprovalStatement, ...],
    policy: ApprovalPolicy,
    *,
    manifest_hash: str,
    approval_policy_bundle_hash: str,
    keyring: Keyring,
    proposer: Principal,
    subject: Principal,
    now: datetime,
) -> QuorumResult:
    """Evaluate ``statements`` against ``policy`` for one exact manifest.

    Raises :class:`ApprovalBatchTooLargeError` if more statements are
    submitted than ``policy.max_statements_considered`` allows -- the
    whole evaluation is rejected rather than silently truncated, since
    dropping an arbitrary statement could change the outcome.

    Never raises for an individual bad statement (wrong manifest,
    forged/unknown-key signature, expired, duplicate approver, etc.) --
    those are recorded in ``QuorumResult.rejected`` with a specific
    reason, and the evaluation proceeds over the remaining statements.
    """
    if len(statements) > policy.max_statements_considered:
        raise ApprovalBatchTooLargeError(
            f"{len(statements)} approval statements submitted, exceeds policy "
            f"max_statements_considered={policy.max_statements_considered}"
        )

    rejected: list[tuple[str, str]] = []
    survivors: list[ApprovalStatement] = []
    for stmt in statements:
        reason = _reject_reason(
            stmt,
            manifest_hash=manifest_hash,
            approval_policy_bundle_hash=approval_policy_bundle_hash,
            policy=policy,
            proposer=proposer,
            subject=subject,
            keyring=keyring,
            now=now,
        )
        if reason is not None:
            rejected.append((stmt.statement_id, reason))
        else:
            survivors.append(stmt)

    authoritative, superseded = _select_authoritative(survivors)
    rejected.extend(superseded)

    approving = sorted(
        (s for s in authoritative.values() if s.decision == "approve"),
        key=lambda s: s.approver.principal_id,
    )
    dissenting = sorted(
        (s for s in authoritative.values() if s.decision == "dissent"),
        key=lambda s: s.approver.principal_id,
    )

    approving_principal_ids = tuple(s.approver.principal_id for s in approving)
    dissenting_principal_ids = tuple(s.approver.principal_id for s in dissenting)
    roles_present = {s.role for s in approving if s.role is not None}
    missing_roles = tuple(sorted(r for r in policy.required_roles if r not in roles_present))
    approval_set_hash = canonical_hash(sorted(s.canonical_hash() for s in approving))

    satisfied = len(approving) >= policy.required_approvals and not missing_roles
    if policy.veto_on_any_dissent and dissenting:
        satisfied = False

    cooling_off_remaining = 0.0
    if satisfied and policy.cooling_off_seconds > 0 and approving:
        earliest = min(s.signed_at for s in approving)
        ready_at = earliest + timedelta(seconds=policy.cooling_off_seconds)
        if now < ready_at:
            satisfied = False
            cooling_off_remaining = (ready_at - now).total_seconds()

    reason_parts = [
        f"{len(approving)}/{policy.required_approvals} required approvals "
        f"from {approving_principal_ids or 'no one'}."
    ]
    if missing_roles:
        reason_parts.append(f"Missing required roles: {list(missing_roles)}.")
    if policy.veto_on_any_dissent and dissenting:
        reason_parts.append(f"Vetoed by dissent from {dissenting_principal_ids}.")
    if cooling_off_remaining > 0:
        reason_parts.append(
            f"Cooling-off period not yet elapsed ({cooling_off_remaining:.0f}s remaining)."
        )
    if rejected:
        reason_parts.append(f"{len(rejected)} statement(s) rejected: {rejected}.")
    reason_parts.append("QUORUM MET." if satisfied else "QUORUM NOT MET.")

    return QuorumResult(
        satisfied=satisfied,
        approving_count=len(approving),
        approving_principal_ids=approving_principal_ids,
        dissenting_principal_ids=dissenting_principal_ids,
        missing_roles=missing_roles,
        rejected=tuple(rejected),
        reason=" ".join(reason_parts),
        approval_set_hash=approval_set_hash,
    )


__all__ = ["evaluate_quorum"]
