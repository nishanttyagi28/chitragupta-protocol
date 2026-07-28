"""Facts about a proposed effect that the Effect Intelligence Engine needs
but cannot derive from the manifest alone: things a production deployment
would source from the delegation/grant chain, an adapter's declared
capabilities, a tenant/policy service, or the audit journal's own history.

Every field defaults to an explicit "unknown" or "none observed" value
(``None`` for optional booleans, ``0`` for counts) rather than a favorable
guess. The scoring engine never treats an unknown fact as favorably as a
confirmed one -- see operating rule #9 ("reject uncertain security
states") applied to risk scoring, not just to cryptographic verification.
"""

from __future__ import annotations

from dataclasses import dataclass

from karmasakshi.audit.journal import AuditJournal
from karmasakshi.domain.manifest import EffectManifest

#: Audit event types that represent a terminal failure of a previously
#: prepared manifest, used to compute historical failure rate.
_FAILURE_EVENT_TYPES = frozenset(
    {
        "effect.commit_failed",
        "effect.commit_error",
        "effect.stale_manifest",
        "effect.precondition_check_error",
    }
)


@dataclass(frozen=True)
class AssessmentFacts:
    delegation_depth: int = 0
    historical_recurrence_count: int = 0
    historical_failure_count: int = 0
    provider_idempotent: bool | None = None
    compensation_feasible: bool | None = None
    cross_tenant: bool = False
    unusual_parameter_change: bool = False
    policy_violations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.delegation_depth < 0:
            raise ValueError("delegation_depth must be >= 0")
        if self.historical_recurrence_count < 0:
            raise ValueError("historical_recurrence_count must be >= 0")
        if self.historical_failure_count < 0:
            raise ValueError("historical_failure_count must be >= 0")
        if self.historical_failure_count > self.historical_recurrence_count:
            raise ValueError("historical_failure_count cannot exceed historical_recurrence_count")
        for v in self.policy_violations:
            if not v or len(v) > 256:
                raise ValueError("policy_violations entries must be 1-256 chars")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "delegation_depth": self.delegation_depth,
            "historical_recurrence_count": self.historical_recurrence_count,
            "historical_failure_count": self.historical_failure_count,
            "provider_idempotent": self.provider_idempotent,
            "compensation_feasible": self.compensation_feasible,
            "cross_tenant": self.cross_tenant,
            "unusual_parameter_change": self.unusual_parameter_change,
            "policy_violations": sorted(self.policy_violations),
        }


def derive_facts_from_audit(
    journal: AuditJournal,
    manifest: EffectManifest,
    *,
    delegation_depth: int = 0,
    provider_idempotent: bool | None = None,
    compensation_feasible: bool | None = None,
    cross_tenant: bool = False,
    unusual_parameter_change: bool = False,
    extra_policy_violations: tuple[str, ...] = (),
) -> AssessmentFacts:
    """Populate historical-recurrence facts from the audit journal's own
    record of this actor performing this effect type before, and pass the
    remaining facts through unchanged (they are not currently derivable
    from the audit journal alone -- see docs/effect-intelligence.md for
    what a production deployment would wire up instead).

    Correlation is by (actor_id, effect_type) via ``manifest.prepared``
    events' metadata, joined against later terminal events for the same
    ``manifest_id`` -- a real query over the hash-chained audit trail, not
    a stub.
    """
    events = journal.all_events()
    prior_manifest_ids: set[str] = set()
    for event in events:
        if (
            event.event_type == "manifest.prepared"
            and event.actor_id == manifest.actor.principal_id
            and event.metadata.get("effect_type") == manifest.effect_type
            and event.manifest_id is not None
            and event.manifest_id != manifest.manifest_id
        ):
            prior_manifest_ids.add(event.manifest_id)

    failed_manifest_ids: set[str] = set()
    for event in events:
        if event.manifest_id in prior_manifest_ids and event.event_type in _FAILURE_EVENT_TYPES:
            failed_manifest_ids.add(event.manifest_id)

    return AssessmentFacts(
        delegation_depth=delegation_depth,
        historical_recurrence_count=len(prior_manifest_ids),
        historical_failure_count=len(failed_manifest_ids),
        provider_idempotent=provider_idempotent,
        compensation_feasible=compensation_feasible,
        cross_tenant=cross_tenant,
        unusual_parameter_change=unusual_parameter_change,
        policy_violations=tuple(extra_policy_violations),
    )


__all__ = ["AssessmentFacts", "derive_facts_from_audit"]
