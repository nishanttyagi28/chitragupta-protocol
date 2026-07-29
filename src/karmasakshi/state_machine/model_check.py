"""Bounded lifecycle state-machine model checking (extreme-v2 Phase 22).

Exhaustively explores the ``TRANSITIONS`` graph up to a depth bound and
checks structural safety properties. This is **not** a TLA+/Alloy proof —
it is a deterministic, bounded checker over the finite lifecycle graph.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from itertools import pairwise

from karmasakshi.state_machine.states import (
    TERMINAL_STATES,
    TRANSITIONS,
    LifecycleState,
    is_legal_transition,
    is_terminal,
)


@dataclass(frozen=True)
class ModelCheckFinding:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ModelCheckReport:
    findings: tuple[ModelCheckFinding, ...]
    paths_explored: int
    depth_bound: int

    @property
    def passed(self) -> bool:
        return all(f.passed for f in self.findings)


def _reachable(start: LifecycleState = LifecycleState.PROPOSED) -> frozenset[LifecycleState]:
    seen: set[LifecycleState] = {start}
    q: deque[LifecycleState] = deque([start])
    while q:
        cur = q.popleft()
        for nxt in TRANSITIONS.get(cur, frozenset()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return frozenset(seen)


def check_lifecycle_model(*, depth_bound: int = 12) -> ModelCheckReport:
    """Run bounded exhaustive checks over the lifecycle transition graph."""
    if depth_bound < 1:
        raise ValueError("depth_bound must be >= 1")

    findings: list[ModelCheckFinding] = []
    paths = 0

    # 1. Every declared transition is consistent with is_legal_transition.
    inconsistent = []
    for src, targets in TRANSITIONS.items():
        for dst in LifecycleState:
            legal = is_legal_transition(src, dst)
            declared = dst in targets
            if legal != declared:
                inconsistent.append(f"{src.value}->{dst.value}")
    findings.append(
        ModelCheckFinding(
            name="transition_table_consistent",
            passed=not inconsistent,
            detail="ok" if not inconsistent else ",".join(inconsistent[:20]),
        )
    )

    # 2. Terminal states have empty outgoing sets.
    bad_terminals = [s.value for s in TERMINAL_STATES if TRANSITIONS.get(s, frozenset())]
    findings.append(
        ModelCheckFinding(
            name="terminals_have_no_exits",
            passed=not bad_terminals,
            detail="ok" if not bad_terminals else ",".join(bad_terminals),
        )
    )

    # 3. Happy path exists: PROPOSED ... VERIFIED within bound.
    happy = (
        LifecycleState.PROPOSED,
        LifecycleState.PREPARED,
        LifecycleState.SEALED,
        LifecycleState.AUTHORIZED,
        LifecycleState.COMMITTING,
        LifecycleState.COMMITTED,
        LifecycleState.VERIFIED,
    )
    happy_ok = all(is_legal_transition(a, b) for a, b in pairwise(happy))
    findings.append(
        ModelCheckFinding(
            name="happy_path_legal",
            passed=happy_ok,
            detail="ok" if happy_ok else "happy path broken",
        )
    )

    # 4. Bounded path enumeration: no path exceeds depth_bound without
    #    terminating or looping; every path's steps are legal.
    q: deque[tuple[LifecycleState, ...]] = deque([(LifecycleState.PROPOSED,)])
    illegal_path = None
    while q:
        path = q.popleft()
        paths += 1
        if len(path) > depth_bound:
            continue
        cur = path[-1]
        if is_terminal(cur):
            continue
        nexts = TRANSITIONS.get(cur, frozenset())
        if not nexts and cur not in TERMINAL_STATES:
            illegal_path = path
            break
        for nxt in sorted(nexts, key=lambda s: s.value):
            if not is_legal_transition(cur, nxt):
                illegal_path = (*path, nxt)
                break
            # Avoid trivial self-cycles exploding the queue.
            if nxt in path and nxt not in TERMINAL_STATES:
                continue
            q.append((*path, nxt))
        if illegal_path is not None:
            break

    findings.append(
        ModelCheckFinding(
            name="bounded_paths_legal",
            passed=illegal_path is None,
            detail="ok" if illegal_path is None else "->".join(s.value for s in illegal_path),
        )
    )

    # 5. All non-start states that appear in TRANSITIONS are reachable
    #    from PROPOSED (no orphan states).
    reachable = _reachable()
    orphans = [
        s.value
        for s in LifecycleState
        if s not in reachable and s != LifecycleState.PROPOSED and TRANSITIONS.get(s) is not None
    ]
    # States only reachable as targets still count via _reachable.
    findings.append(
        ModelCheckFinding(
            name="no_orphan_states",
            passed=len(reachable) == len(LifecycleState),
            detail=f"reachable={len(reachable)}/{len(LifecycleState)}"
            if len(reachable) == len(LifecycleState)
            else f"orphans={orphans}",
        )
    )

    # 6. COMMITTING is not revocable (invariant #27 structural).
    from karmasakshi.state_machine.states import REVOCABLE_STATES

    findings.append(
        ModelCheckFinding(
            name="committing_not_revocable",
            passed=LifecycleState.COMMITTING not in REVOCABLE_STATES,
            detail="ok",
        )
    )

    return ModelCheckReport(
        findings=tuple(findings),
        paths_explored=paths,
        depth_bound=depth_bound,
    )


__all__ = ["ModelCheckFinding", "ModelCheckReport", "check_lifecycle_model"]
