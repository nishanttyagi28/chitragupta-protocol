from __future__ import annotations

import contextlib
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from chitragupta.errors import IllegalTransitionError
from chitragupta.state_machine import LifecycleRecord, LifecycleState
from chitragupta.state_machine.states import TRANSITIONS, is_legal_transition

_now = datetime(2026, 1, 1, tzinfo=timezone.utc)
_states = st.sampled_from(list(LifecycleState))


@given(st.lists(_states, min_size=1, max_size=25))
@settings(max_examples=300, deadline=None)
def test_lifecycle_record_only_ever_reaches_states_reachable_via_legal_transitions(targets):
    record = LifecycleRecord(manifest_id="m1")
    for target in targets:
        current = record.state
        if is_legal_transition(current, target):
            record.transition(target, at=_now)
            assert record.state == target
        else:
            try:
                record.transition(target, at=_now)
                illegal_was_rejected = False
            except IllegalTransitionError:
                illegal_was_rejected = True
            assert illegal_was_rejected
            assert record.state == current  # state must be unchanged after a rejected transition


@given(_states, _states)
@settings(max_examples=200, deadline=None)
def test_is_legal_transition_matches_transitions_graph_exactly(current, target):
    assert is_legal_transition(current, target) == (target in TRANSITIONS.get(current, frozenset()))


@given(st.lists(_states, min_size=0, max_size=25))
@settings(max_examples=200, deadline=None)
def test_history_length_equals_number_of_accepted_transitions(targets):
    record = LifecycleRecord(manifest_id="m1")
    accepted = 0
    for target in targets:
        if is_legal_transition(record.state, target):
            record.transition(target, at=_now)
            accepted += 1
        else:
            with contextlib.suppress(IllegalTransitionError):
                record.transition(target, at=_now)
    assert len(record.history) == accepted
