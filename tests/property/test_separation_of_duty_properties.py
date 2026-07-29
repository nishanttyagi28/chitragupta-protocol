"""Property-based tests for separation-of-duty enforcement determinism
(extreme-v2 Phase 4), mirroring the order-independence guarantees already
proven for quorum evaluation (Phase 3)."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from karmasakshi.duty import ProtocolRole, RoleAssignment, SeparationOfDutyPolicy
from karmasakshi.duty.enforcement import check_separation_of_duty

_MANIFEST_HASH = "sha256:" + "1" * 64

_ROLE_VALUES = tuple(r.value for r in ProtocolRole)

_principal_ids = st.text(
    alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=8
).map(lambda s: f"user:{s}")

_roles = st.sampled_from(_ROLE_VALUES)


@st.composite
def _role_assignments(draw: st.DrawFn) -> RoleAssignment:
    n = draw(st.integers(min_value=0, max_value=12))
    pairs = draw(st.lists(st.tuples(_roles, _principal_ids), min_size=n, max_size=n, unique=True))
    return RoleAssignment(manifest_hash=_MANIFEST_HASH, assignments=tuple(pairs))


@st.composite
def _separation_policies(draw: st.DrawFn) -> SeparationOfDutyPolicy:
    n = draw(st.integers(min_value=0, max_value=6))
    raw_pairs = draw(
        st.lists(
            st.tuples(_roles, _roles).filter(lambda p: p[0] != p[1]),
            min_size=0,
            max_size=n * 2,
        )
    )
    # de-duplicate order-independently before handing to the policy, which
    # itself rejects duplicate unordered pairs
    seen: set[frozenset[str]] = set()
    pairs: list[tuple[str, str]] = []
    for a, b in raw_pairs:
        key = frozenset({a, b})
        if key in seen:
            continue
        seen.add(key)
        pairs.append((a, b))
    return SeparationOfDutyPolicy(forbidden_role_pairs=tuple(pairs))


@given(assignment=_role_assignments(), policy=_separation_policies())
def test_check_result_is_independent_of_assignment_entry_order(assignment, policy):
    reordered = RoleAssignment(
        manifest_hash=assignment.manifest_hash,
        assignments=tuple(reversed(assignment.assignments)),
    )
    result_a = check_separation_of_duty(assignment, policy)
    result_b = check_separation_of_duty(reordered, policy)
    assert result_a.satisfied == result_b.satisfied
    assert set(result_a.violations) == set(result_b.violations)


@given(assignment=_role_assignments(), policy=_separation_policies())
def test_check_result_is_independent_of_forbidden_pair_order(assignment, policy):
    reordered_policy = SeparationOfDutyPolicy(
        forbidden_role_pairs=tuple(reversed(policy.forbidden_role_pairs))
    )
    result_a = check_separation_of_duty(assignment, policy)
    result_b = check_separation_of_duty(assignment, reordered_policy)
    assert result_a.satisfied == result_b.satisfied
    assert set(result_a.violations) == set(result_b.violations)


@given(assignment=_role_assignments())
def test_empty_forbidden_matrix_is_always_satisfied(assignment):
    result = check_separation_of_duty(assignment, SeparationOfDutyPolicy(forbidden_role_pairs=()))
    assert result.satisfied
    assert result.violations == ()


@given(assignment=_role_assignments(), policy=_separation_policies())
def test_adding_more_forbidden_pairs_never_turns_a_violation_into_satisfied(assignment, policy):
    """Monotonicity: a strictly larger forbidden-pair matrix can only add
    violations, never remove ones already found -- separation-of-duty
    checking must never become more permissive as policy grows."""
    extra_pairs = tuple(policy.forbidden_role_pairs[:1])
    if not extra_pairs:
        return
    superset = SeparationOfDutyPolicy(forbidden_role_pairs=policy.forbidden_role_pairs)
    subset_pairs = tuple(p for p in policy.forbidden_role_pairs if p != extra_pairs[0])
    subset = SeparationOfDutyPolicy(forbidden_role_pairs=subset_pairs)

    subset_result = check_separation_of_duty(assignment, subset)
    superset_result = check_separation_of_duty(assignment, superset)
    if subset_result.satisfied is False:
        assert superset_result.satisfied is False
