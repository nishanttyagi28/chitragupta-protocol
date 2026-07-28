"""The lifecycle state machine: PROPOSE -> PREPARE -> SEAL -> AUTHORIZE ->
COMMIT -> VERIFY -> PROVE.

Legal transitions are modeled explicitly as a graph. Illegal transitions
raise :class:`~karmasakshi.errors.IllegalTransitionError` deterministically
and never perform the external effect (see docs/state-machine.md for the
full transition diagram and rationale).
"""

from __future__ import annotations

from enum import Enum

from karmasakshi.errors import IllegalTransitionError


class LifecycleState(str, Enum):
    PROPOSED = "proposed"
    PREPARED = "prepared"
    SEALED = "sealed"
    AUTHORIZED = "authorized"
    COMMITTING = "committing"
    COMMITTED = "committed"
    VERIFIED = "verified"
    FAILED = "failed"
    REVOKED = "revoked"
    EXPIRED = "expired"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"


#: States from which a grant/manifest may still be revoked at a safe
#: checkpoint (invariant #27: revocation only stops execution at defined
#: safe checkpoints -- never mid external call).
REVOCABLE_STATES = frozenset(
    {
        LifecycleState.PROPOSED,
        LifecycleState.PREPARED,
        LifecycleState.SEALED,
        LifecycleState.AUTHORIZED,
    }
)

#: Terminal states: no outgoing transitions.
TERMINAL_STATES = frozenset(
    {
        LifecycleState.FAILED,
        LifecycleState.REVOKED,
        LifecycleState.EXPIRED,
        LifecycleState.COMPENSATED,
    }
)

TRANSITIONS: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.PROPOSED: frozenset(
        {LifecycleState.PREPARED, LifecycleState.FAILED, LifecycleState.REVOKED}
    ),
    LifecycleState.PREPARED: frozenset(
        {
            LifecycleState.SEALED,
            LifecycleState.FAILED,
            LifecycleState.REVOKED,
            LifecycleState.EXPIRED,
        }
    ),
    LifecycleState.SEALED: frozenset(
        {
            LifecycleState.AUTHORIZED,
            LifecycleState.FAILED,
            LifecycleState.REVOKED,
            LifecycleState.EXPIRED,
        }
    ),
    LifecycleState.AUTHORIZED: frozenset(
        {
            LifecycleState.COMMITTING,
            LifecycleState.FAILED,
            LifecycleState.REVOKED,
            LifecycleState.EXPIRED,
        }
    ),
    LifecycleState.COMMITTING: frozenset({LifecycleState.COMMITTED, LifecycleState.FAILED}),
    LifecycleState.COMMITTED: frozenset({LifecycleState.VERIFIED}),
    LifecycleState.VERIFIED: frozenset({LifecycleState.COMPENSATING, LifecycleState.COMPENSATED}),
    LifecycleState.COMPENSATING: frozenset({LifecycleState.COMPENSATED, LifecycleState.FAILED}),
    LifecycleState.FAILED: frozenset(),
    LifecycleState.REVOKED: frozenset(),
    LifecycleState.EXPIRED: frozenset(),
    LifecycleState.COMPENSATED: frozenset(),
}


def is_legal_transition(current: LifecycleState, target: LifecycleState) -> bool:
    return target in TRANSITIONS.get(current, frozenset())


def assert_legal_transition(current: LifecycleState, target: LifecycleState) -> None:
    if not is_legal_transition(current, target):
        raise IllegalTransitionError(
            f"illegal lifecycle transition: {current.value} -> {target.value}"
        )


def is_revocable(current: LifecycleState) -> bool:
    return current in REVOCABLE_STATES


def is_terminal(current: LifecycleState) -> bool:
    return current in TERMINAL_STATES


__all__ = [
    "REVOCABLE_STATES",
    "TERMINAL_STATES",
    "TRANSITIONS",
    "LifecycleState",
    "assert_legal_transition",
    "is_legal_transition",
    "is_revocable",
    "is_terminal",
]
