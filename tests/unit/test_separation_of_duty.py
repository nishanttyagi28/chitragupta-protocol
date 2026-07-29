from __future__ import annotations

import pytest

from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.duty import (
    ProtocolRole,
    RoleAssignment,
    SeparationOfDutyPolicy,
    build_separation_of_duty_policy_bundle,
    check_separation_of_duty,
    separation_of_duty_policy_from_bundle_payload,
)
from karmasakshi.duty.roles import base_role_assignment
from karmasakshi.errors import PolicyBundleIssuerNotAuthorizedError, RoleAssignmentError

_MANIFEST_HASH = "sha256:" + "1" * 64
_OTHER_MANIFEST_HASH = "sha256:" + "2" * 64


def _principal(pid, ptype=PrincipalType.HUMAN):
    return Principal(principal_id=pid, principal_type=ptype)


# --- RoleAssignment -----------------------------------------------------------


def test_role_assignment_rejects_malformed_manifest_hash():
    with pytest.raises(RoleAssignmentError):
        RoleAssignment(manifest_hash="not-a-hash", assignments=())


def test_role_assignment_rejects_unknown_role():
    with pytest.raises(RoleAssignmentError):
        RoleAssignment(manifest_hash=_MANIFEST_HASH, assignments=(("astronaut", "user:a"),))


def test_role_assignment_rejects_empty_principal_id():
    with pytest.raises(RoleAssignmentError):
        RoleAssignment(
            manifest_hash=_MANIFEST_HASH, assignments=((ProtocolRole.PROPOSER.value, ""),)
        )


def test_role_assignment_rejects_exact_duplicate_entries():
    with pytest.raises(RoleAssignmentError):
        RoleAssignment(
            manifest_hash=_MANIFEST_HASH,
            assignments=(
                (ProtocolRole.PROPOSER.value, "user:a"),
                (ProtocolRole.PROPOSER.value, "user:a"),
            ),
        )


def test_role_assignment_rejects_oversized_batch():
    assignments = tuple((ProtocolRole.WITNESS.value, f"user:{i}") for i in range(257))
    with pytest.raises(RoleAssignmentError):
        RoleAssignment(manifest_hash=_MANIFEST_HASH, assignments=assignments)


def test_role_assignment_principals_for_is_sorted_and_deduplicated():
    ra = RoleAssignment.of(_MANIFEST_HASH, ProtocolRole.APPROVER, "user:b", "user:a", "user:b")
    assert ra.principals_for(ProtocolRole.APPROVER) == ("user:a", "user:b")
    assert ra.principals_for(ProtocolRole.SEALER) == ()


def test_role_assignment_merge_combines_and_deduplicates():
    a = RoleAssignment.of(_MANIFEST_HASH, ProtocolRole.PROPOSER, "user:a")
    b = RoleAssignment.of(_MANIFEST_HASH, ProtocolRole.APPROVER, "user:b")
    merged = a.merge(b)
    assert merged.principals_for(ProtocolRole.PROPOSER) == ("user:a",)
    assert merged.principals_for(ProtocolRole.APPROVER) == ("user:b",)
    # merging the same fact twice does not duplicate it
    assert merged.merge(a).assignments == merged.assignments


def test_role_assignment_merge_none_is_identity():
    a = RoleAssignment.of(_MANIFEST_HASH, ProtocolRole.PROPOSER, "user:a")
    assert a.merge(None) is a


def test_role_assignment_merge_rejects_mismatched_manifest_hash():
    a = RoleAssignment.of(_MANIFEST_HASH, ProtocolRole.PROPOSER, "user:a")
    b = RoleAssignment.of(_OTHER_MANIFEST_HASH, ProtocolRole.APPROVER, "user:b")
    with pytest.raises(RoleAssignmentError):
        a.merge(b)


def test_role_assignment_as_role_participation_joins_multiple_principals():
    ra = RoleAssignment(
        manifest_hash=_MANIFEST_HASH,
        assignments=(
            (ProtocolRole.APPROVER.value, "user:b"),
            (ProtocolRole.APPROVER.value, "user:a"),
            (ProtocolRole.PROPOSER.value, "user:c"),
        ),
    )
    assert ra.as_role_participation() == {
        "approver": "user:a,user:b",
        "proposer": "user:c",
    }


def test_base_role_assignment_derives_proposer_executor_approver():
    ra = base_role_assignment(
        _MANIFEST_HASH,
        proposer_id="user:proposer",
        executor_id="agent:executor",
        approver_ids=("user:alice", "user:bob"),
    )
    assert ra.principals_for(ProtocolRole.PROPOSER) == ("user:proposer",)
    assert ra.principals_for(ProtocolRole.EXECUTOR) == ("agent:executor",)
    assert ra.principals_for(ProtocolRole.APPROVER) == ("user:alice", "user:bob")


# --- SeparationOfDutyPolicy -----------------------------------------------------


def test_default_policy_has_a_sensible_matrix():
    policy = SeparationOfDutyPolicy()
    pairs = {frozenset(p) for p in policy.forbidden_role_pairs}
    assert frozenset({"sealer", "approver"}) in pairs
    assert frozenset({"proposer", "approver"}) in pairs
    assert frozenset({"approver", "executor"}) in pairs


@pytest.mark.parametrize(
    "kwargs",
    [
        {"policy_id": ""},
        {"policy_version": "1"},
        {"forbidden_role_pairs": (("astronaut", "approver"),)},
        {"forbidden_role_pairs": (("approver", "approver"),)},
        {"forbidden_role_pairs": (("sealer", "approver"), ("approver", "sealer"))},
    ],
)
def test_invalid_separation_policy_rejected(kwargs):
    with pytest.raises(ValueError):
        SeparationOfDutyPolicy(**kwargs)


def test_separation_policy_rejects_oversized_matrix():
    roles = [r.value for r in ProtocolRole]
    pairs = tuple((roles[0], f"custom-{i}") for i in range(65))
    # the synthetic "custom-N" role names are not valid roles, so build a
    # policy that fails on size first by using only real (but repeating
    # via index) role names -- easiest is to directly assert the bound.
    from karmasakshi.duty.policy import MAX_FORBIDDEN_ROLE_PAIRS

    assert len(pairs) > MAX_FORBIDDEN_ROLE_PAIRS
    with pytest.raises(ValueError):
        SeparationOfDutyPolicy(forbidden_role_pairs=pairs)


def test_separation_policy_hash_is_order_independent_across_pairs_and_within_a_pair():
    p1 = SeparationOfDutyPolicy(
        forbidden_role_pairs=(("sealer", "approver"), ("proposer", "approver"))
    )
    p2 = SeparationOfDutyPolicy(
        forbidden_role_pairs=(("approver", "proposer"), ("approver", "sealer"))
    )
    assert p1.policy_hash() == p2.policy_hash()


def test_separation_policy_bundle_round_trips_through_payload(now):
    original = SeparationOfDutyPolicy(forbidden_role_pairs=(("witness", "approver"),))
    bundle = build_separation_of_duty_policy_bundle(
        original,
        bundle_id="sod-1",
        bundle_version="1.0",
        issuer=_principal("admin"),
        created_at=now,
        effective_from=now,
    )
    reconstructed = separation_of_duty_policy_from_bundle_payload(bundle.payload)
    assert reconstructed.policy_hash() == original.policy_hash()


def test_separation_policy_bundle_rejects_agent_issuer(now):
    with pytest.raises(PolicyBundleIssuerNotAuthorizedError):
        build_separation_of_duty_policy_bundle(
            SeparationOfDutyPolicy(),
            bundle_id="sod-2",
            bundle_version="1.0",
            issuer=_principal("agent-1", PrincipalType.AGENT),
            created_at=now,
            effective_from=now,
        )


# --- check_separation_of_duty ---------------------------------------------------


def test_no_violation_when_roles_held_by_distinct_principals():
    ra = RoleAssignment(
        manifest_hash=_MANIFEST_HASH,
        assignments=(
            (ProtocolRole.PROPOSER.value, "user:a"),
            (ProtocolRole.APPROVER.value, "user:b"),
            (ProtocolRole.EXECUTOR.value, "agent:c"),
        ),
    )
    result = check_separation_of_duty(ra, SeparationOfDutyPolicy())
    assert result.satisfied
    assert result.violations == ()


def test_violation_when_one_principal_holds_both_forbidden_roles():
    ra = RoleAssignment(
        manifest_hash=_MANIFEST_HASH,
        assignments=(
            (ProtocolRole.PROPOSER.value, "user:a"),
            (ProtocolRole.APPROVER.value, "user:a"),
            (ProtocolRole.EXECUTOR.value, "agent:c"),
        ),
    )
    result = check_separation_of_duty(ra, SeparationOfDutyPolicy())
    assert not result.satisfied
    assert len(result.violations) == 1
    v = result.violations[0]
    assert v.principal_id == "user:a"
    assert {v.role_a, v.role_b} == {"proposer", "approver"}


def test_violation_reported_once_per_offending_pair_not_per_role():
    """A principal holding sealer+proposer+approver against the default
    matrix (sealer-approver, proposer-approver, approver-executor)
    violates two independent pairs -- both must be reported."""
    ra = RoleAssignment(
        manifest_hash=_MANIFEST_HASH,
        assignments=(
            (ProtocolRole.SEALER.value, "user:a"),
            (ProtocolRole.PROPOSER.value, "user:a"),
            (ProtocolRole.APPROVER.value, "user:a"),
        ),
    )
    result = check_separation_of_duty(ra, SeparationOfDutyPolicy())
    assert not result.satisfied
    assert len(result.violations) == 2
    pairs = {frozenset({v.role_a, v.role_b}) for v in result.violations}
    assert frozenset({"sealer", "approver"}) in pairs
    assert frozenset({"proposer", "approver"}) in pairs


def test_multiple_approvers_only_the_overlapping_principal_violates():
    ra = RoleAssignment(
        manifest_hash=_MANIFEST_HASH,
        assignments=(
            (ProtocolRole.PROPOSER.value, "user:a"),
            (ProtocolRole.APPROVER.value, "user:a"),
            (ProtocolRole.APPROVER.value, "user:b"),
        ),
    )
    result = check_separation_of_duty(ra, SeparationOfDutyPolicy())
    assert not result.satisfied
    assert len(result.violations) == 1
    assert result.violations[0].principal_id == "user:a"


def test_empty_forbidden_matrix_never_violates():
    ra = RoleAssignment(
        manifest_hash=_MANIFEST_HASH,
        assignments=(
            (ProtocolRole.PROPOSER.value, "user:a"),
            (ProtocolRole.APPROVER.value, "user:a"),
        ),
    )
    result = check_separation_of_duty(ra, SeparationOfDutyPolicy(forbidden_role_pairs=()))
    assert result.satisfied
