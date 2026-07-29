"""Engine helper: assert independent witness quorum (Phase 9)."""

from __future__ import annotations

from datetime import datetime

from karmasakshi.crypto.keyring import Keyring
from karmasakshi.domain.common import Principal
from karmasakshi.errors import WitnessQuorumNotMetError
from karmasakshi.witness.model import WitnessPolicy, WitnessQuorumResult, WitnessStatement
from karmasakshi.witness.quorum import evaluate_witness_quorum


def assert_witness_quorum(
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
    """Evaluate witness quorum; raise if policy is not satisfied."""
    result = evaluate_witness_quorum(
        statements,
        policy,
        manifest_hash=manifest_hash,
        expected_after_state_digest=expected_after_state_digest,
        actor=actor,
        subject=subject,
        keyring=keyring,
        now=now,
    )
    if not result.satisfied:
        reasons = "; ".join(result.rejection_reasons) or "insufficient distinct witnesses"
        raise WitnessQuorumNotMetError(
            f"witness quorum not met for manifest {manifest_hash}: "
            f"accepted={len(result.accepted_witness_ids)} "
            f"required={policy.required_witnesses}; {reasons}"
        )
    return result


__all__ = ["assert_witness_quorum"]
