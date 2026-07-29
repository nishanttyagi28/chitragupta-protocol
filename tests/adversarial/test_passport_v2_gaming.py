from __future__ import annotations

from datetime import datetime, timezone

from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType, ReversibilityClassification, RiskClassification
from karmasakshi.passports.model import ActionPassport, PassportVerificationStatus
from karmasakshi.passports.v2 import OutcomeStatus, derive_outcome_status


def _passport(**overrides: object) -> ActionPassport:
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


def test_adversary_cannot_force_verified_match_from_executor_success_alone() -> None:
    """Commit success without independent observation must not become VERIFIED_MATCH."""
    p = _passport(
        commit_attempted=True,
        commit_success=True,
        observed_matched_expected=None,
        lifecycle_state="committed",
        grant_id="g1",
    )
    assert derive_outcome_status(p) == OutcomeStatus.COMMITTED_UNVERIFIED
    assert derive_outcome_status(p) is not OutcomeStatus.VERIFIED_MATCH


def test_adversary_cannot_erase_mismatch_with_compensation_pointer_only() -> None:
    """Compensation pointers alone do not upgrade a mismatch to verified match."""
    p = _passport(
        commit_attempted=True,
        commit_success=True,
        observed_matched_expected=False,
        compensation_manifest_hash="sha256:" + ("c" * 64),
        compensation_passport_status="pending",
        lifecycle_state="verified",
        grant_id="g1",
    )
    assert derive_outcome_status(p) == OutcomeStatus.VERIFIED_MISMATCH
