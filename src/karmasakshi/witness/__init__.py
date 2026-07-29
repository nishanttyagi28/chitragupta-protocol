"""Independent witness quorum (Phase 9).

Witnesses observe outcomes after COMMIT/VERIFY. They are not approval
grants and must not be issued by agents. Quorum evaluation is
deterministic and fails closed on mismatch, expiry, or insufficient count.
"""

from __future__ import annotations

from karmasakshi.witness.model import (
    DEFAULT_WITNESS_POLICY,
    WitnessPolicy,
    WitnessQuorumResult,
    WitnessStatement,
)
from karmasakshi.witness.quorum import evaluate_witness_quorum
from karmasakshi.witness.signing import (
    sign_witness_statement,
    verify_witness_statement_signature,
    verify_witness_statement_time_window,
)

__all__ = [
    "DEFAULT_WITNESS_POLICY",
    "WitnessPolicy",
    "WitnessQuorumResult",
    "WitnessStatement",
    "evaluate_witness_quorum",
    "sign_witness_statement",
    "verify_witness_statement_signature",
    "verify_witness_statement_time_window",
]
