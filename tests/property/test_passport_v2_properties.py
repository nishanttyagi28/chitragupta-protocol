from __future__ import annotations

from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType, ReversibilityClassification, RiskClassification
from karmasakshi.passports.model import ActionPassport, PassportVerificationStatus
from karmasakshi.passports.v2 import OutcomeStatus, derive_outcome_status


def make_minimal_passport(**overrides: object) -> ActionPassport:
    base: dict[str, object] = {
        "generated_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "manifest_id": "m1",
        "manifest_hash": "sha256:" + ("b" * 64),
        "effect_type": "payment.refund",
        "actor": Principal(principal_id="a1", principal_type=PrincipalType.AGENT),
        "principal": Principal(principal_id="p1", principal_type=PrincipalType.HUMAN),
        "target_resource": "payment:1",
        "proposed_parameters": {},
        "risk": RiskClassification.MEDIUM,
        "reversibility": ReversibilityClassification.REVERSIBLE,
        "lifecycle_state": "authorized",
        "verification": PassportVerificationStatus(
            seal_verified=True, grant_verified=True, audit_chain_verified=True
        ),
    }
    base.update(overrides)
    return ActionPassport(**base)  # type: ignore[arg-type]


@given(
    matched=st.one_of(st.none(), st.booleans()),
    commit_success=st.one_of(st.none(), st.booleans()),
    commit_attempted=st.booleans(),
    was_revoked=st.booleans(),
)
@settings(max_examples=80)
def test_derive_outcome_status_is_deterministic_enum(
    matched: bool | None,
    commit_success: bool | None,
    commit_attempted: bool,
    was_revoked: bool,
) -> None:
    p = make_minimal_passport(
        observed_matched_expected=matched,
        commit_success=commit_success,
        commit_attempted=commit_attempted,
        was_revoked=was_revoked,
        grant_id="g1",
        lifecycle_state="revoked" if was_revoked else "committed",
    )
    status = derive_outcome_status(p)
    assert isinstance(status, OutcomeStatus)
    assert derive_outcome_status(p) == status
