"""Durable persistence for the Gateway refund journey's per-tenant,
in-memory `ApiState` dicts (RA-002 follow-up).

`rehydrate_tenant_registrations` (see `karmasakshi.gateway.api`) already
rebuilds the tenant control-plane registry and reopens each tenant's durable
audit/grant/lifecycle SQLite stores after a process restart. That alone left
a refund that was **fully committed and independently verified** before the
restart -- the product's central evidentiary artifact, including its Action
Passport -- completely inaccessible afterward: the Gateway's own
refund-journey read-model state (`ApiState.sealed_manifests`,
`.assessments`, `.grants`, `.grants_by_manifest`, `.commit_results`,
`.outcome_proofs`, `.policy_bundles`, `.assessment_policy_bundles`,
`.approval_policy_bundles`, `.approval_statements`,
`.active_policy_bundle_id`) is plain process-local Python dict state, never
durable on its own.

This module writes each of those dicts' mutations through to the Gateway's
SQLite store (`GatewayStore.put_refund_state`), keyed per organization, and
rebuilds them from it at startup (`rehydrate_refund_state`). Callers in
`karmasakshi.gateway.refunds` call the `persist_*` functions immediately
after each corresponding in-memory mutation; this module does not decide
*when* to persist, only *how*.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from karmasakshi.adapters.base import CommitResult, OutcomeProof
from karmasakshi.approval.model import ApprovalStatement
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.intelligence.model import EffectAssessment
from karmasakshi.policy.bundle import SealedPolicyBundle

if TYPE_CHECKING:
    from karmasakshi.api.state import ApiState
    from karmasakshi.gateway.store import GatewayStore

_ACTIVE_POLICY_BUNDLE_ID_KEY = "_"


def _dump_commit_result(result: CommitResult) -> dict[str, Any]:
    return {
        "success": result.success,
        "idempotency_key": result.idempotency_key,
        "provider_reference": result.provider_reference,
        "detail": result.detail,
        "after_state_digest": result.after_state_digest,
    }


def _load_commit_result(payload: dict[str, Any]) -> CommitResult:
    return CommitResult(**payload)


def _dump_outcome_proof(proof: OutcomeProof) -> dict[str, Any]:
    return {
        "matched_expected": proof.matched_expected,
        "observed_at": proof.observed_at.isoformat(),
        "observed_after_state_digest": proof.observed_after_state_digest,
        "detail": proof.detail,
    }


def _load_outcome_proof(payload: dict[str, Any]) -> OutcomeProof:
    data = dict(payload)
    data["observed_at"] = datetime.fromisoformat(data["observed_at"])
    return OutcomeProof(**data)


def persist_sealed_manifest(store: GatewayStore, org_id: str, sealed: SealedManifest) -> None:
    store.put_refund_state(
        org_id, "sealed_manifest", sealed.manifest.manifest_id, sealed.model_dump(mode="json")
    )


def persist_assessment(
    store: GatewayStore, org_id: str, manifest_id: str, assessment: EffectAssessment
) -> None:
    store.put_refund_state(org_id, "assessment", manifest_id, assessment.model_dump(mode="json"))


def persist_grant_and_index(
    store: GatewayStore,
    org_id: str,
    manifest_id: str,
    grant: ExecutionGrant,
    grant_ids: list[str],
) -> None:
    store.put_refund_state(org_id, "grant", grant.grant_id, grant.model_dump(mode="json"))
    store.put_refund_state(org_id, "grants_by_manifest", manifest_id, list(grant_ids))


def persist_commit_result(
    store: GatewayStore, org_id: str, manifest_id: str, result: CommitResult
) -> None:
    store.put_refund_state(org_id, "commit_result", manifest_id, _dump_commit_result(result))


def persist_outcome_proof(
    store: GatewayStore, org_id: str, manifest_id: str, proof: OutcomeProof
) -> None:
    store.put_refund_state(org_id, "outcome_proof", manifest_id, _dump_outcome_proof(proof))


def persist_policy_bundle(
    store: GatewayStore, org_id: str, bundle_id: str, bundle: SealedPolicyBundle
) -> None:
    store.put_refund_state(org_id, "policy_bundle", bundle_id, bundle.model_dump(mode="json"))


def persist_active_policy_bundle_id(
    store: GatewayStore, org_id: str, bundle_id: str | None
) -> None:
    store.put_refund_state(
        org_id, "active_policy_bundle_id", _ACTIVE_POLICY_BUNDLE_ID_KEY, bundle_id
    )


def persist_approval_policy_bundle(
    store: GatewayStore, org_id: str, manifest_id: str, bundle: SealedPolicyBundle
) -> None:
    store.put_refund_state(
        org_id, "approval_policy_bundle", manifest_id, bundle.model_dump(mode="json")
    )


def persist_assessment_policy_bundle(
    store: GatewayStore, org_id: str, manifest_id: str, bundle: SealedPolicyBundle
) -> None:
    store.put_refund_state(
        org_id, "assessment_policy_bundle", manifest_id, bundle.model_dump(mode="json")
    )


def persist_approval_statements(
    store: GatewayStore, org_id: str, manifest_id: str, statements: list[ApprovalStatement]
) -> None:
    store.put_refund_state(
        org_id,
        "approval_statements",
        manifest_id,
        [s.model_dump(mode="json") for s in statements],
    )


def rehydrate_refund_state(store: GatewayStore, org_id: str, runtime: ApiState) -> None:
    """Rebuild ``runtime``'s refund-journey dicts from durable storage.
    Idempotent and additive: only ever inserts, never called on a runtime
    that already has in-memory entries (a fresh `ApiState` from
    `create_tenant()`)."""
    buckets = store.load_refund_state(org_id)
    for manifest_id, payload in buckets.get("sealed_manifest", {}).items():
        runtime.sealed_manifests[manifest_id] = SealedManifest.model_validate(payload)
    for manifest_id, payload in buckets.get("assessment", {}).items():
        runtime.assessments[manifest_id] = EffectAssessment.model_validate(payload)
    for grant_id, payload in buckets.get("grant", {}).items():
        runtime.grants[grant_id] = ExecutionGrant.model_validate(payload)
    for manifest_id, payload in buckets.get("grants_by_manifest", {}).items():
        runtime.grants_by_manifest[manifest_id] = list(cast("list[str]", payload))
    for manifest_id, payload in buckets.get("commit_result", {}).items():
        runtime.commit_results[manifest_id] = _load_commit_result(cast("dict[str, Any]", payload))
    for manifest_id, payload in buckets.get("outcome_proof", {}).items():
        runtime.outcome_proofs[manifest_id] = _load_outcome_proof(cast("dict[str, Any]", payload))
    for bundle_id, payload in buckets.get("policy_bundle", {}).items():
        runtime.policy_bundles[bundle_id] = SealedPolicyBundle.model_validate(payload)
    for manifest_id, payload in buckets.get("approval_policy_bundle", {}).items():
        runtime.approval_policy_bundles[manifest_id] = SealedPolicyBundle.model_validate(payload)
    for manifest_id, payload in buckets.get("assessment_policy_bundle", {}).items():
        runtime.assessment_policy_bundles[manifest_id] = SealedPolicyBundle.model_validate(payload)
    for manifest_id, payload in buckets.get("approval_statements", {}).items():
        runtime.approval_statements[manifest_id] = [
            ApprovalStatement.model_validate(s) for s in cast("list[Any]", payload)
        ]
    active_id_bucket = buckets.get("active_policy_bundle_id", {})
    if _ACTIVE_POLICY_BUNDLE_ID_KEY in active_id_bucket:
        runtime.active_policy_bundle_id = cast(
            "str | None", active_id_bucket[_ACTIVE_POLICY_BUNDLE_ID_KEY]
        )


__all__ = [
    "persist_active_policy_bundle_id",
    "persist_approval_policy_bundle",
    "persist_approval_statements",
    "persist_assessment",
    "persist_assessment_policy_bundle",
    "persist_commit_result",
    "persist_grant_and_index",
    "persist_outcome_proof",
    "persist_policy_bundle",
    "persist_sealed_manifest",
    "rehydrate_refund_state",
]
