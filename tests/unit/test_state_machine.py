from __future__ import annotations

import itertools

import pytest

from karmasakshi.errors import IllegalTransitionError
from karmasakshi.state_machine import (
    LifecycleRecord,
    LifecycleState,
    assert_legal_transition,
    is_legal_transition,
    is_revocable,
    is_terminal,
)

HAPPY_PATH = [
    LifecycleState.PROPOSED,
    LifecycleState.PREPARED,
    LifecycleState.SEALED,
    LifecycleState.AUTHORIZED,
    LifecycleState.COMMITTING,
    LifecycleState.COMMITTED,
    LifecycleState.VERIFIED,
    LifecycleState.COMPENSATED,
]


def test_happy_path_is_legal():
    for a, b in itertools.pairwise(HAPPY_PATH):
        assert is_legal_transition(a, b), f"{a} -> {b} should be legal"


@pytest.mark.parametrize(
    "current,target",
    [
        (LifecycleState.PROPOSED, LifecycleState.AUTHORIZED),
        (LifecycleState.PROPOSED, LifecycleState.COMMITTED),
        (LifecycleState.PREPARED, LifecycleState.AUTHORIZED),
        (LifecycleState.SEALED, LifecycleState.COMMITTED),
        (LifecycleState.AUTHORIZED, LifecycleState.VERIFIED),
        (LifecycleState.COMMITTING, LifecycleState.VERIFIED),
        (LifecycleState.COMMITTED, LifecycleState.COMMITTING),
        (LifecycleState.COMMITTED, LifecycleState.REVOKED),
        (LifecycleState.VERIFIED, LifecycleState.COMMITTING),
        (LifecycleState.FAILED, LifecycleState.COMMITTED),
        (LifecycleState.REVOKED, LifecycleState.AUTHORIZED),
        (LifecycleState.EXPIRED, LifecycleState.AUTHORIZED),
        (LifecycleState.COMPENSATED, LifecycleState.VERIFIED),
    ],
)
def test_illegal_transitions_rejected(current, target):
    assert not is_legal_transition(current, target)
    with pytest.raises(IllegalTransitionError):
        assert_legal_transition(current, target)


def test_terminal_states_have_no_outgoing_transitions():
    for state in (
        LifecycleState.FAILED,
        LifecycleState.REVOKED,
        LifecycleState.EXPIRED,
        LifecycleState.COMPENSATED,
    ):
        assert is_terminal(state)
        for other in LifecycleState:
            assert not is_legal_transition(state, other)


def test_committing_committed_verified_are_not_revocable():
    assert not is_revocable(LifecycleState.COMMITTING)
    assert not is_revocable(LifecycleState.COMMITTED)
    assert not is_revocable(LifecycleState.VERIFIED)


def test_pre_commit_states_are_revocable():
    for state in (
        LifecycleState.PROPOSED,
        LifecycleState.PREPARED,
        LifecycleState.SEALED,
        LifecycleState.AUTHORIZED,
    ):
        assert is_revocable(state)


def test_lifecycle_record_tracks_history(now):
    record = LifecycleRecord(manifest_id="m1")
    record.transition(LifecycleState.PREPARED, at=now)
    record.transition(LifecycleState.SEALED, at=now)
    assert record.state == LifecycleState.SEALED
    assert record.history == [
        (LifecycleState.PROPOSED, LifecycleState.PREPARED, now),
        (LifecycleState.PREPARED, LifecycleState.SEALED, now),
    ]


def test_lifecycle_record_rejects_illegal_transition(now):
    record = LifecycleRecord(manifest_id="m1")
    with pytest.raises(IllegalTransitionError):
        record.transition(LifecycleState.COMMITTED, at=now)
    # state must be unchanged and history untouched after a rejected transition
    assert record.state == LifecycleState.PROPOSED
    assert record.history == []


def test_every_non_terminal_state_can_reach_a_terminal_state():
    # Reachability sanity check via BFS over the transition graph.
    from karmasakshi.state_machine.states import TERMINAL_STATES, TRANSITIONS

    for start in LifecycleState:
        if start in TERMINAL_STATES:
            continue
        seen = {start}
        frontier = [start]
        reached_terminal = False
        while frontier:
            node = frontier.pop()
            for nxt in TRANSITIONS.get(node, frozenset()):
                if nxt in TERMINAL_STATES:
                    reached_terminal = True
                    break
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append(nxt)
            if reached_terminal:
                break
        assert reached_terminal, f"{start} cannot reach any terminal state"
