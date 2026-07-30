"""The core engine: orchestrates PROPOSE -> PREPARE -> ASSESS -> SEAL ->
AUTHORIZE -> COMMIT -> VERIFY, delegating the external effect to an
:class:`EffectAdapter` while owning every security decision itself
(invariant #30: the adapter/agent never decides authorization). ASSESS
(see :meth:`KarmaSakshiEngine.assess`) is an audited side-channel step,
not a lifecycle-state transition -- see docs/effect-intelligence.md.

See docs/architecture.md for the full sequence diagram.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, NoReturn

from karmasakshi.adapters.base import (
    CommitResult,
    CompensationResult,
    EffectAdapter,
    OutcomeProof,
)
from karmasakshi.approval.model import ApprovalStatement
from karmasakshi.approval.policy import POLICY_TYPE_APPROVAL, approval_policy_from_bundle_payload
from karmasakshi.approval.quorum import evaluate_quorum
from karmasakshi.budget.consume import require_budget, resolve_budget_consume_amount
from karmasakshi.causal.graph import CausalEffectGraph
from karmasakshi.compensation.manifest import assert_compensation_binds_original
from karmasakshi.compensation.status import CompensationStatus
from karmasakshi.crypto.keys import SigningKey
from karmasakshi.delegation.attenuation import assert_grant_narrower_or_equal
from karmasakshi.delegation.revocation import assert_no_revoked_ancestors
from karmasakshi.domain.common import Principal
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.duty.enforcement import check_separation_of_duty
from karmasakshi.duty.policy import (
    POLICY_TYPE_SEPARATION,
    separation_of_duty_policy_from_bundle_payload,
)
from karmasakshi.duty.roles import RoleAssignment, base_role_assignment
from karmasakshi.engine.context import EngineContext
from karmasakshi.envelope.model import DecisionEnvelope, assert_manifest_fits_envelope
from karmasakshi.envelope.plan import assert_manifest_in_plan, require_matching_plan_hash
from karmasakshi.envelope.sealing import verify_decision_envelope
from karmasakshi.errors import (
    AdapterMismatchError,
    AtomicPlanError,
    AuthorityBudgetError,
    AuthorityBudgetExhaustedError,
    CompensationBindingError,
    DecisionEnvelopeMismatchError,
    DelegationLineageError,
    EvidenceQualityError,
    GrantAudienceError,
    GrantExhaustedError,
    GrantManifestMismatchError,
    GrantRevokedError,
    KarmaSakshiError,
    PolicyBundleMismatchError,
    QuorumNotMetError,
    SagaAmbiguousStepError,
    SagaGraphMismatchError,
    SagaIllegalTransitionError,
    SeparationOfDutyViolationError,
    StaleManifestError,
    StoreUnavailableError,
    TenantIsolationError,
    UntrustedAdapterError,
    WitnessQuorumNotMetError,
)
from karmasakshi.evidence.evaluate import evaluate_evidence_quality
from karmasakshi.evidence.model import EvidenceAssessment, EvidencePolicy, EvidenceRecord
from karmasakshi.grants.issuer import issue_grant
from karmasakshi.grants.model import ExecutionGrant, ScopeConstraints
from karmasakshi.grants.verifier import verify_grant
from karmasakshi.intelligence.engine import EffectIntelligenceEngine
from karmasakshi.intelligence.facts import AssessmentFacts
from karmasakshi.intelligence.model import EffectAssessment
from karmasakshi.intelligence.policy import IntelligencePolicy
from karmasakshi.observability.model import ObservabilityEvent, ObservabilityEventType
from karmasakshi.observability.sinks import emit_safely
from karmasakshi.outbox.memory import OutboxConflictError
from karmasakshi.outbox.model import OutboxEntry
from karmasakshi.policy.bundle import SealedPolicyBundle
from karmasakshi.policy.sealing import verify_policy_bundle
from karmasakshi.protocol.sealing import seal_manifest, verify_seal
from karmasakshi.saga.machine import (
    assert_can_commit_step,
    assert_can_recover_step,
    mark_compensation_result,
    mark_step_ambiguous,
    mark_step_authorized,
    mark_step_committed,
    mark_step_failed,
    mark_step_verified,
    next_compensation_manifest_hash,
)
from karmasakshi.saga.model import (
    SagaRun,
    SagaRunStatus,
    SagaStepStatus,
    build_saga_plan,
    build_saga_run,
)
from karmasakshi.state_machine.record import LifecycleRecord
from karmasakshi.state_machine.states import LifecycleState, is_revocable
from karmasakshi.tenant.enforce import bind_engine_and_policy_tenant
from karmasakshi.witness.model import WitnessPolicy, WitnessQuorumResult, WitnessStatement
from karmasakshi.witness.quorum import evaluate_witness_quorum


def _role_participation_metadata(role_assignment: RoleAssignment) -> dict[str, str]:
    """Flatten a :class:`RoleAssignment` into ``dict[str, str]`` audit
    metadata, one ``role:<role>`` key per role actually present."""
    return {
        f"role:{role}": principal_ids
        for role, principal_ids in role_assignment.as_role_participation().items()
    }


class KarmaSakshiEngine:
    """Stateful orchestrator. One instance per process/session is typical;
    lifecycle records are held in memory keyed by manifest_id (the durable
    record of what happened lives in ``context.audit``)."""

    def __init__(self, context: EngineContext) -> None:
        self._ctx = context
        self._records: dict[str, LifecycleRecord] = {}
        self._saga_runs: dict[str, SagaRun] = {}

    def _record_grant_lineage(self, grant: ExecutionGrant) -> None:
        """Persist parent pointer so commit can walk deep revocation (Phase 11)."""
        if grant.parent_grant_id is None:
            return
        self._ctx.grant_store.record_lineage(grant.grant_id, grant.parent_grant_id)

    def _assert_authority_budget_registered(self, authority_budget_id: str | None) -> None:
        """Fail closed if a grant binds a budget the ledger does not know."""
        if authority_budget_id is None:
            return
        require_budget(self._ctx.budget_ledger, authority_budget_id)

    @property
    def context(self) -> EngineContext:
        return self._ctx

    def get_lifecycle_state(self, manifest_id: str) -> LifecycleState:
        return self._get_record(manifest_id).state

    def seed_lifecycle_state(self, manifest_id: str, state: LifecycleState) -> None:
        """Seed the in-memory lifecycle record for ``manifest_id`` to ``state``
        without performing a transition or writing an audit event.

        This engine's lifecycle records are process-local by default; the
        durable record of what actually happened lives in the audit journal.
        A long-running host that reconstructs a fresh engine per invocation
        (the CLI, in particular) uses this to restore the correct starting
        state from the audit journal before continuing the lifecycle --
        never to fabricate a state that didn't actually happen.

        When ``EngineContext.lifecycle_store`` is configured (Phase 13), the
        seeded state is also written through to that store.
        """
        self._records[manifest_id] = LifecycleRecord(manifest_id=manifest_id, state=state)
        store = self._ctx.lifecycle_store
        if store is not None:
            store.set(manifest_id, state)

    def _get_record(self, manifest_id: str) -> LifecycleRecord:
        record = self._records.get(manifest_id)
        if record is not None:
            return record
        store = self._ctx.lifecycle_store
        if store is not None:
            stored = store.get(manifest_id)
            if stored is not None:
                record = LifecycleRecord(manifest_id=manifest_id, state=stored)
                self._records[manifest_id] = record
                return record
        record = LifecycleRecord(manifest_id=manifest_id)
        self._records[manifest_id] = record
        return record

    def _persist_lifecycle(
        self, manifest_id: str, from_state: LifecycleState, target: LifecycleState
    ) -> None:
        """Write-through to the durable lifecycle store; fail closed on error."""
        store = self._ctx.lifecycle_store
        if store is None:
            return
        # First write uses expected=None only when the record was never stored.
        expected: LifecycleState | None = from_state
        if store.get(manifest_id) is None and from_state == LifecycleState.PROPOSED:
            # Lazy in-memory PROPOSED has no row yet - insert as target.
            # If a concurrent writer inserted first, retry with expected PROPOSED.
            if not (
                store.compare_and_set(manifest_id, None, target)
                or store.compare_and_set(manifest_id, from_state, target)
            ):
                raise StoreUnavailableError(
                    f"lifecycle store compare_and_set failed for {manifest_id} "
                    f"({from_state.value} -> {target.value})"
                )
            return
        if not store.compare_and_set(manifest_id, expected, target):
            raise StoreUnavailableError(
                f"lifecycle store compare_and_set failed for {manifest_id} "
                f"({from_state.value} -> {target.value}); refuse to continue with "
                "uncertain durable lifecycle state"
            )

    def _transition(
        self,
        manifest_id: str,
        target: LifecycleState,
        *,
        event_type: str,
        grant_id: str | None = None,
        manifest_hash: str | None = None,
        actor_id: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> LifecycleRecord:
        record = self._get_record(manifest_id)
        from_state = record.state
        try:
            record.transition(target, at=self._ctx.clock.now())
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type=event_type,
                decision="blocked_illegal_transition",
                manifest_id=manifest_id,
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                from_state=from_state.value,
                to_state=target.value,
                metadata=metadata or {},
            )
            raise
        try:
            self._persist_lifecycle(manifest_id, from_state, target)
        except StoreUnavailableError:
            # Roll back the in-memory advance so a failed durable write never
            # leaves memory ahead of storage (fail closed).
            self._records[manifest_id] = LifecycleRecord(
                manifest_id=manifest_id, state=from_state, history=list(record.history[:-1])
            )
            self._ctx.audit.record(
                event_type=event_type,
                decision="blocked_lifecycle_store_unavailable",
                manifest_id=manifest_id,
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                from_state=from_state.value,
                to_state=target.value,
                metadata=metadata or {},
            )
            raise
        self._ctx.audit.record(
            event_type=event_type,
            decision="allowed",
            manifest_id=manifest_id,
            manifest_hash=manifest_hash,
            grant_id=grant_id,
            actor_id=actor_id,
            from_state=from_state.value,
            to_state=target.value,
            metadata=metadata or {},
        )
        return record

    # --- PROPOSE ------------------------------------------------------------

    def propose(
        self, *, actor: Principal, effect_type: str, summary: dict[str, str] | None = None
    ) -> str:
        """Log the raw proposal before it is resolved into a manifest.

        Returns a ``proposal_id`` correlating this proposal with the
        eventual manifest in the audit trail. Manifest resolution happens
        in :meth:`prepare`.
        """
        proposal_id = str(uuid.uuid4())
        self._ctx.audit.record(
            event_type="effect.proposed",
            decision="proposed",
            actor_id=actor.principal_id,
            metadata={"proposal_id": proposal_id, "effect_type": effect_type, **(summary or {})},
        )
        return proposal_id

    def _require_trusted_adapter(
        self,
        adapter: EffectAdapter,
        *,
        effect_type: str | None = None,
    ) -> None:
        """Fail closed when a registry is configured and the adapter is untrusted.

        Additive: when ``adapter_registry`` is ``None``, this is a no-op
        (Phases 1-16 behavior). Exact ``(adapter_id, adapter_version)`` pins
        only — no semver ranges.
        """
        registry = self._ctx.adapter_registry
        if registry is None:
            return
        if effect_type is None:
            registry.require_adapter(adapter)
        else:
            registry.require_effect(adapter.adapter_id, adapter.adapter_version, effect_type)

    def _enforce_policy_tenant(self, policy_bundle: SealedPolicyBundle | None) -> None:
        """Fail closed on tenant uncertainty / cross-tenant policy use (Phase 19).

        When neither the engine nor the bundle declares a tenant, legacy
        single-tenant behaviour is preserved. When either declares one, both
        must be present and equal.
        """
        if policy_bundle is None and self._ctx.tenant_id is None:
            return
        policy_tenant = None if policy_bundle is None else policy_bundle.bundle.tenant_id
        try:
            bind_engine_and_policy_tenant(
                engine_tenant_id=self._ctx.tenant_id,
                policy_tenant_id=policy_tenant,
            )
        except TenantIsolationError:
            raise

    # --- PREPARE --------------------------------------------------------------

    def prepare(self, adapter: EffectAdapter, request: Any, context: Any) -> EffectManifest:
        self._require_trusted_adapter(adapter)
        manifest = adapter.prepare(request, context)
        # Re-check after prepare: identity/version and declared effect type.
        self._require_trusted_adapter(adapter, effect_type=manifest.effect_type)
        if (
            manifest.adapter.adapter_id != adapter.adapter_id
            or manifest.adapter.adapter_version != adapter.adapter_version
        ):
            raise AdapterMismatchError(
                f"adapter.prepare returned manifest for "
                f"{manifest.adapter.adapter_id}@{manifest.adapter.adapter_version}, "
                f"but executing adapter is {adapter.adapter_id}@{adapter.adapter_version}"
            )
        self._transition(
            manifest.manifest_id,
            LifecycleState.PREPARED,
            event_type="manifest.prepared",
            manifest_hash=manifest.canonical_hash(),
            actor_id=manifest.actor.principal_id,
            metadata={"adapter_id": adapter.adapter_id, "effect_type": manifest.effect_type},
        )
        return manifest

    def prepare_compensation(
        self,
        compensation_manifest: EffectManifest,
        *,
        original_sealed: SealedManifest,
    ) -> EffectManifest:
        """Register a pre-built compensation manifest as PREPARED.

        Unlike :meth:`prepare`, this does not call ``adapter.prepare`` — the
        compensation manifest is constructed by
        ``compensation.build_compensation_manifest`` and must already bind
        the original sealed hash.
        """
        verify_seal(original_sealed, self._ctx.keyring)
        assert_compensation_binds_original(compensation_manifest, original_sealed)
        self._transition(
            compensation_manifest.manifest_id,
            LifecycleState.PREPARED,
            event_type="compensation.manifest.prepared",
            manifest_hash=compensation_manifest.canonical_hash(),
            actor_id=compensation_manifest.actor.principal_id,
            metadata={
                "original_manifest_id": original_sealed.manifest.manifest_id,
                "original_manifest_hash": original_sealed.seal.manifest_hash,
                "effect_type": compensation_manifest.effect_type,
            },
        )
        return compensation_manifest

    # --- ASSESS -------------------------------------------------------------

    def assess(
        self,
        manifest: EffectManifest,
        facts: AssessmentFacts | None = None,
        *,
        policy: IntelligencePolicy | None = None,
    ) -> EffectAssessment:
        """Run the deterministic Effect Intelligence Engine over ``manifest``
        and record the result in the audit journal.

        Like :meth:`propose`, this does not transition the lifecycle state
        machine -- it is an audited side-channel evaluation that may be
        invoked any number of times (e.g. re-assessed after new facts
        arrive) between :meth:`prepare` and :meth:`authorize`. The returned
        recommendation is advisory in this protocol version: nothing in
        :meth:`authorize`/:meth:`commit` currently reads or enforces it.
        See docs/effect-intelligence.md.

        If ``policy`` is given, this call is scored against that policy
        instead of the engine context's configured default -- e.g. a
        caller-verified, currently-activated organization
        ``IntelligencePolicy`` -- without mutating the engine's own bound
        policy or affecting any other call.
        """
        scorer = (
            self._ctx.intelligence
            if policy is None
            else EffectIntelligenceEngine(policy, clock=self._ctx.clock)
        )
        assessment = scorer.assess(manifest, facts)
        self._ctx.audit.record(
            event_type="effect.assessed",
            decision=assessment.recommendation.value,
            manifest_id=manifest.manifest_id,
            manifest_hash=assessment.manifest_hash,
            actor_id=manifest.actor.principal_id,
            metadata={
                "assessment_id": assessment.assessment_id,
                "score": str(assessment.score),
                "risk_level": assessment.risk_level.value,
                "policy_id": assessment.policy_id,
                "policy_hash": assessment.policy_hash,
                "required_human_approvals": str(assessment.required_human_approvals),
            },
        )
        return assessment

    # --- OBSERVE (Phase 24) ------------------------------------------------

    def observe(
        self,
        event_type: ObservabilityEventType,
        manifest_id: str,
        *,
        manifest_hash: str | None = None,
        grant_id: str | None = None,
        decision: str | None = None,
        detail: str | None = None,
    ) -> ObservabilityEvent:
        """Emit a best-effort observability event for external log/metrics
        consumption (extreme-v2 Phase 24).

        This is advisory only: unlike :meth:`assess`, it is never recorded
        in the tamper-evident audit journal, it never gates any lifecycle
        transition, and a failing sink never raises here (see
        ``karmasakshi.observability.sinks.emit_safely``). Like
        :meth:`assess`, callers (CLI/API) invoke this explicitly at
        meaningful lifecycle points rather than it being automatically
        wired into :meth:`authorize`/:meth:`commit` -- see
        docs/observability.md.
        """
        lifecycle_state = self.get_lifecycle_state(manifest_id).value
        event = ObservabilityEvent(
            event_type=event_type,
            emitted_at=self._ctx.clock.now(),
            manifest_id=manifest_id,
            manifest_hash=manifest_hash,
            grant_id=grant_id,
            lifecycle_state=lifecycle_state,
            decision=decision,
            tenant_id=self._ctx.tenant_id,
            detail=detail,
        )
        emit_safely(self._ctx.observability_sink, event)
        return event

    # --- SEAL -------------------------------------------------------------

    def seal(self, manifest: EffectManifest, signing_key: SigningKey) -> SealedManifest:
        sealed = seal_manifest(manifest, signing_key, clock=self._ctx.clock)
        self._transition(
            manifest.manifest_id,
            LifecycleState.SEALED,
            event_type="manifest.sealed",
            manifest_hash=sealed.seal.manifest_hash,
            actor_id=manifest.actor.principal_id,
            metadata={"key_id": signing_key.key_id},
        )
        return sealed

    # --- AUTHORIZE ------------------------------------------------------------

    def authorize(
        self,
        sealed: SealedManifest,
        *,
        issuer: Principal,
        subject: Principal,
        audience: tuple[str, ...],
        allowed_effect_types: tuple[str, ...],
        scope: ScopeConstraints,
        not_before: datetime,
        expires_at: datetime,
        signing_key: SigningKey,
        grant_id: str | None = None,
        nonce: str | None = None,
        max_uses: int = 1,
        parent_grant_id: str | None = None,
        authority_budget_id: str | None = None,
        policy_bundle: SealedPolicyBundle | None = None,
        separation_policy_bundle: SealedPolicyBundle | None = None,
        role_assignment: RoleAssignment | None = None,
    ) -> ExecutionGrant:
        """Issue an :class:`ExecutionGrant` bound to ``sealed``.

        If ``policy_bundle`` is given, it is verified (signature, tamper,
        and effective-window checks -- see
        ``policy.sealing.verify_policy_bundle``) before the grant is
        issued, and its hash is bound into the grant's own signed payload
        (``ExecutionGrant.policy_bundle_hash``). A later policy edit
        cannot silently change what this grant authorizes: the grant's
        signature already covers the old bundle's hash, and
        :meth:`commit` requires the *same* bundle (by hash) to be
        re-presented and re-verified before the effect executes.

        If ``separation_policy_bundle`` is given (extreme-v2 Phase 4:
        Separation of Duties, ``policy_type == "separation.v1"``), the
        engine builds the base role facts it already knows about this
        call (``proposer`` = ``sealed.manifest.actor``, ``executor`` =
        ``subject``, ``approver`` = ``issuer``), merges in any additional
        roles from ``role_assignment`` (e.g. ``sealer``, ``witness``),
        and checks the combined assignment against the bundle's
        forbidden role-pair matrix via
        ``duty.enforcement.check_separation_of_duty``. A violation blocks
        grant issuance entirely (:class:`SeparationOfDutyViolationError`)
        -- see docs/separation-of-duties.md.

        ``authority_budget_id`` (Phase 12) optionally binds the grant to a
        registered shared AuthorityBudget; ``commit`` consumes that budget
        atomically. Distinct from ``scope.max_amount``.
        """
        verify_seal(sealed, self._ctx.keyring)
        manifest_hash = sealed.seal.manifest_hash
        self._assert_authority_budget_registered(authority_budget_id)
        if policy_bundle is not None:
            try:
                verify_policy_bundle(policy_bundle, self._ctx.keyring, now=self._ctx.clock.now())
            except KarmaSakshiError:
                self._ctx.audit.record(
                    event_type="policy_bundle.verification_failed",
                    decision="blocked",
                    manifest_id=sealed.manifest.manifest_id,
                    manifest_hash=manifest_hash,
                    actor_id=issuer.principal_id,
                    metadata={"bundle_id": policy_bundle.bundle.bundle_id},
                )
                raise
            self._enforce_policy_tenant(policy_bundle)
        policy_bundle_hash = policy_bundle.seal.bundle_hash if policy_bundle is not None else None

        combined_roles = base_role_assignment(
            manifest_hash,
            proposer_id=sealed.manifest.actor.principal_id,
            executor_id=subject.principal_id,
            approver_ids=(issuer.principal_id,),
        ).merge(role_assignment)
        if separation_policy_bundle is not None:
            self._enforce_separation_of_duty(
                separation_policy_bundle,
                combined_roles,
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=issuer.principal_id,
            )

        try:
            grant = issue_grant(
                grant_id=grant_id or str(uuid.uuid4()),
                issuer=issuer,
                subject=subject,
                audience=audience,
                allowed_effect_types=allowed_effect_types,
                scope=scope,
                not_before=not_before,
                expires_at=expires_at,
                nonce=nonce or uuid.uuid4().hex,
                signing_key=signing_key,
                manifest_hash=manifest_hash,
                policy_bundle_hash=policy_bundle_hash,
                max_uses=max_uses,
                parent_grant_id=parent_grant_id,
                authority_budget_id=authority_budget_id,
                clock=self._ctx.clock,
            )
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="grant.issue_denied",
                decision="blocked",
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=issuer.principal_id,
            )
            raise
        self._transition(
            sealed.manifest.manifest_id,
            LifecycleState.AUTHORIZED,
            event_type="grant.issued",
            manifest_hash=manifest_hash,
            grant_id=grant.grant_id,
            actor_id=issuer.principal_id,
            metadata={
                "subject": subject.principal_id,
                **({"policy_bundle_hash": policy_bundle_hash} if policy_bundle_hash else {}),
                **({"authority_budget_id": authority_budget_id} if authority_budget_id else {}),
                **_role_participation_metadata(combined_roles),
            },
        )
        self._record_grant_lineage(grant)
        return grant

    # --- PHASE 6: DECISION ENVELOPES / ATOMIC PLAN AUTHORIZATION ----------

    def authorize_with_envelope(
        self,
        sealed: SealedManifest,
        envelope: DecisionEnvelope,
        *,
        issuer: Principal,
        subject: Principal,
        audience: tuple[str, ...],
        allowed_effect_types: tuple[str, ...],
        scope: ScopeConstraints,
        not_before: datetime,
        expires_at: datetime,
        signing_key: SigningKey,
        grant_id: str | None = None,
        nonce: str | None = None,
        max_uses: int = 1,
        parent_grant_id: str | None = None,
        authority_budget_id: str | None = None,
        policy_bundle: SealedPolicyBundle | None = None,
        separation_policy_bundle: SealedPolicyBundle | None = None,
        role_assignment: RoleAssignment | None = None,
    ) -> ExecutionGrant:
        """Issue a grant bound to ``sealed`` *and* a verified Decision Envelope.

        The sealed manifest must fit the envelope's constrained parameter
        space (``assert_manifest_fits_envelope``). The envelope's hash is
        bound into the grant (``decision_envelope_hash``); ``commit()``
        requires the same envelope to be re-presented and re-checked.
        Mutually exclusive with :meth:`authorize_plan` -- this path never
        sets ``causal_graph_hash`` on the grant (if the envelope itself
        pins a ``causal_graph_hash``, that binding lives inside the
        envelope hash, not as a separate grant field).
        """
        verify_seal(sealed, self._ctx.keyring)
        manifest_hash = sealed.seal.manifest_hash
        self._assert_authority_budget_registered(authority_budget_id)
        try:
            verify_decision_envelope(envelope, self._ctx.keyring, now=self._ctx.clock.now())
            assert_manifest_fits_envelope(sealed.manifest, envelope)
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="decision_envelope.authorization_failed",
                decision="blocked",
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=issuer.principal_id,
                metadata={"envelope_id": envelope.envelope_id},
            )
            raise

        envelope_hash = envelope.canonical_hash()
        if policy_bundle is not None:
            try:
                verify_policy_bundle(policy_bundle, self._ctx.keyring, now=self._ctx.clock.now())
            except KarmaSakshiError:
                self._ctx.audit.record(
                    event_type="policy_bundle.verification_failed",
                    decision="blocked",
                    manifest_id=sealed.manifest.manifest_id,
                    manifest_hash=manifest_hash,
                    actor_id=issuer.principal_id,
                    metadata={"bundle_id": policy_bundle.bundle.bundle_id},
                )
                raise
            self._enforce_policy_tenant(policy_bundle)
        policy_bundle_hash = policy_bundle.seal.bundle_hash if policy_bundle is not None else None

        combined_roles = base_role_assignment(
            manifest_hash,
            proposer_id=sealed.manifest.actor.principal_id,
            executor_id=subject.principal_id,
            approver_ids=(issuer.principal_id,),
        ).merge(role_assignment)
        if separation_policy_bundle is not None:
            self._enforce_separation_of_duty(
                separation_policy_bundle,
                combined_roles,
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=issuer.principal_id,
            )

        try:
            grant = issue_grant(
                grant_id=grant_id or str(uuid.uuid4()),
                issuer=issuer,
                subject=subject,
                audience=audience,
                allowed_effect_types=allowed_effect_types,
                scope=scope,
                not_before=not_before,
                expires_at=expires_at,
                nonce=nonce or uuid.uuid4().hex,
                signing_key=signing_key,
                manifest_hash=manifest_hash,
                policy_bundle_hash=policy_bundle_hash,
                decision_envelope_hash=envelope_hash,
                max_uses=max_uses,
                parent_grant_id=parent_grant_id,
                authority_budget_id=authority_budget_id,
                clock=self._ctx.clock,
            )
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="grant.issue_denied",
                decision="blocked",
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=issuer.principal_id,
            )
            raise
        self._transition(
            sealed.manifest.manifest_id,
            LifecycleState.AUTHORIZED,
            event_type="grant.issued",
            manifest_hash=manifest_hash,
            grant_id=grant.grant_id,
            actor_id=issuer.principal_id,
            metadata={
                "subject": subject.principal_id,
                "decision_envelope_hash": envelope_hash,
                "envelope_id": envelope.envelope_id,
                **({"policy_bundle_hash": policy_bundle_hash} if policy_bundle_hash else {}),
                **_role_participation_metadata(combined_roles),
            },
        )
        return grant

    def authorize_plan(
        self,
        sealed: SealedManifest,
        graph: CausalEffectGraph,
        *,
        issuer: Principal,
        subject: Principal,
        audience: tuple[str, ...],
        allowed_effect_types: tuple[str, ...],
        scope: ScopeConstraints,
        not_before: datetime,
        expires_at: datetime,
        signing_key: SigningKey,
        grant_id: str | None = None,
        nonce: str | None = None,
        max_uses: int = 1,
        parent_grant_id: str | None = None,
        authority_budget_id: str | None = None,
        policy_bundle: SealedPolicyBundle | None = None,
        separation_policy_bundle: SealedPolicyBundle | None = None,
        role_assignment: RoleAssignment | None = None,
    ) -> ExecutionGrant:
        """Issue a grant bound to ``sealed`` *and* one sealed causal graph.

        The sealed manifest's hash must be a node of ``graph`` (atomic plan
        membership). The graph's canonical hash is bound into the grant
        (``causal_graph_hash``); ``commit()`` requires the same graph to be
        re-presented and re-checked. Mutually exclusive with
        :meth:`authorize_with_envelope`.
        """
        verify_seal(sealed, self._ctx.keyring)
        manifest_hash = sealed.seal.manifest_hash
        self._assert_authority_budget_registered(authority_budget_id)
        try:
            assert_manifest_in_plan(manifest_hash, graph, keyring=self._ctx.keyring)
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="atomic_plan.authorization_failed",
                decision="blocked",
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=issuer.principal_id,
                metadata={"graph_id": graph.graph_id},
            )
            raise

        graph_hash = graph.canonical_hash()
        if policy_bundle is not None:
            try:
                verify_policy_bundle(policy_bundle, self._ctx.keyring, now=self._ctx.clock.now())
            except KarmaSakshiError:
                self._ctx.audit.record(
                    event_type="policy_bundle.verification_failed",
                    decision="blocked",
                    manifest_id=sealed.manifest.manifest_id,
                    manifest_hash=manifest_hash,
                    actor_id=issuer.principal_id,
                    metadata={"bundle_id": policy_bundle.bundle.bundle_id},
                )
                raise
            self._enforce_policy_tenant(policy_bundle)
        policy_bundle_hash = policy_bundle.seal.bundle_hash if policy_bundle is not None else None

        combined_roles = base_role_assignment(
            manifest_hash,
            proposer_id=sealed.manifest.actor.principal_id,
            executor_id=subject.principal_id,
            approver_ids=(issuer.principal_id,),
        ).merge(role_assignment)
        if separation_policy_bundle is not None:
            self._enforce_separation_of_duty(
                separation_policy_bundle,
                combined_roles,
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=issuer.principal_id,
            )

        try:
            grant = issue_grant(
                grant_id=grant_id or str(uuid.uuid4()),
                issuer=issuer,
                subject=subject,
                audience=audience,
                allowed_effect_types=allowed_effect_types,
                scope=scope,
                not_before=not_before,
                expires_at=expires_at,
                nonce=nonce or uuid.uuid4().hex,
                signing_key=signing_key,
                manifest_hash=manifest_hash,
                policy_bundle_hash=policy_bundle_hash,
                causal_graph_hash=graph_hash,
                max_uses=max_uses,
                parent_grant_id=parent_grant_id,
                authority_budget_id=authority_budget_id,
                clock=self._ctx.clock,
            )
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="grant.issue_denied",
                decision="blocked",
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=issuer.principal_id,
            )
            raise
        self._transition(
            sealed.manifest.manifest_id,
            LifecycleState.AUTHORIZED,
            event_type="grant.issued",
            manifest_hash=manifest_hash,
            grant_id=grant.grant_id,
            actor_id=issuer.principal_id,
            metadata={
                "subject": subject.principal_id,
                "causal_graph_hash": graph_hash,
                "graph_id": graph.graph_id,
                **({"policy_bundle_hash": policy_bundle_hash} if policy_bundle_hash else {}),
                **_role_participation_metadata(combined_roles),
            },
        )
        return grant

    # --- SEPARATION OF DUTIES (extreme-v2 Phase 4) --------------------------

    def _enforce_separation_of_duty(
        self,
        separation_policy_bundle: SealedPolicyBundle,
        combined_roles: RoleAssignment,
        *,
        manifest_id: str,
        manifest_hash: str,
        actor_id: str,
    ) -> None:
        """Verify ``separation_policy_bundle`` and block on any violation.

        Shared by :meth:`authorize` and :meth:`authorize_with_quorum` --
        the evaluation logic lives once here rather than being
        duplicated, per docs/extreme-v2-build-status.md's Phase 4 scope.
        """
        try:
            verify_policy_bundle(
                separation_policy_bundle,
                self._ctx.keyring,
                now=self._ctx.clock.now(),
                expected_policy_type=POLICY_TYPE_SEPARATION,
            )
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="separation_policy_bundle.verification_failed",
                decision="blocked",
                manifest_id=manifest_id,
                manifest_hash=manifest_hash,
                actor_id=actor_id,
                metadata={"bundle_id": separation_policy_bundle.bundle.bundle_id},
            )
            raise

        separation_policy = separation_of_duty_policy_from_bundle_payload(
            separation_policy_bundle.bundle.payload
        )
        result = check_separation_of_duty(combined_roles, separation_policy)
        self._ctx.audit.record(
            event_type="separation_of_duty.evaluated",
            decision="satisfied" if result.satisfied else "violated",
            manifest_id=manifest_id,
            manifest_hash=manifest_hash,
            actor_id=actor_id,
            metadata={
                "reason": result.reason[:200],
                **_role_participation_metadata(combined_roles),
            },
        )
        if not result.satisfied:
            raise SeparationOfDutyViolationError(
                f"separation of duty violated for manifest {manifest_hash}: {result.reason}"
            )

    # --- AUTHORIZE WITH QUORUM (extreme-v2 Phase 3) --------------------------

    def authorize_with_quorum(
        self,
        sealed: SealedManifest,
        *,
        statements: tuple[ApprovalStatement, ...],
        approval_policy_bundle: SealedPolicyBundle,
        proposer: Principal,
        subject: Principal,
        grant_issuer: Principal,
        audience: tuple[str, ...],
        allowed_effect_types: tuple[str, ...],
        scope: ScopeConstraints,
        not_before: datetime,
        expires_at: datetime,
        signing_key: SigningKey,
        grant_id: str | None = None,
        nonce: str | None = None,
        max_uses: int = 1,
        parent_grant_id: str | None = None,
        authority_budget_id: str | None = None,
        policy_bundle: SealedPolicyBundle | None = None,
        separation_policy_bundle: SealedPolicyBundle | None = None,
        role_assignment: RoleAssignment | None = None,
    ) -> ExecutionGrant:
        """Issue an :class:`ExecutionGrant` only if ``statements`` satisfy
        the quorum rules bound in ``approval_policy_bundle``.

        This is additive: :meth:`authorize` (single-issuer) is unchanged
        and remains fully supported. Here, ``grant_issuer`` is the
        principal recorded as the grant's signing authority (e.g. a
        "quorum service" identity) -- distinct from the individual
        ``statements.approver``s whose collective decision is what
        actually authorizes the effect. Verifies ``approval_policy_bundle``
        (signature, tamper, effective window, and ``policy_type ==
        "approval.v1"``), evaluates ``statements`` against it via
        ``approval.quorum.evaluate_quorum``, and -- only if satisfied --
        binds a hash of the counted approval statements into the issued
        grant (``ExecutionGrant.approval_set_hash``). Raises
        :class:`QuorumNotMetError` (carrying the full ``QuorumResult`` in
        its message) if quorum is not met; the grant is structurally
        impossible to obtain any other way through this method.

        Unlike ``policy_bundle`` binding, the approval set is **not**
        re-verified at :meth:`commit` time: each ``ApprovalStatement`` is
        already an individually signed, immutable historical record
        validated once here, not a mutable, re-editable policy an
        attacker could swap later -- see docs/multi-party-authorization.md
        for the full rationale.

        If ``separation_policy_bundle`` is given (extreme-v2 Phase 4), the
        base role assignment is built from ``proposer``, ``subject``
        (executor), and every principal that satisfied quorum (approver
        -- there may be more than one), merged with any additional roles
        in ``role_assignment``, and checked the same way as in
        :meth:`authorize` -- see docs/separation-of-duties.md.
        """
        verify_seal(sealed, self._ctx.keyring)
        manifest_hash = sealed.seal.manifest_hash
        self._assert_authority_budget_registered(authority_budget_id)
        try:
            verify_policy_bundle(
                approval_policy_bundle,
                self._ctx.keyring,
                now=self._ctx.clock.now(),
                expected_policy_type=POLICY_TYPE_APPROVAL,
            )
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="approval_policy_bundle.verification_failed",
                decision="blocked",
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=grant_issuer.principal_id,
                metadata={"bundle_id": approval_policy_bundle.bundle.bundle_id},
            )
            raise

        approval_policy = approval_policy_from_bundle_payload(approval_policy_bundle.bundle.payload)
        approval_policy_bundle_hash = approval_policy_bundle.seal.bundle_hash
        quorum = evaluate_quorum(
            statements,
            approval_policy,
            manifest_hash=manifest_hash,
            approval_policy_bundle_hash=approval_policy_bundle_hash,
            keyring=self._ctx.keyring,
            proposer=proposer,
            subject=subject,
            now=self._ctx.clock.now(),
        )
        self._ctx.audit.record(
            event_type="approval.quorum_evaluated",
            decision="satisfied" if quorum.satisfied else "not_satisfied",
            manifest_id=sealed.manifest.manifest_id,
            manifest_hash=manifest_hash,
            actor_id=grant_issuer.principal_id,
            metadata={
                "approving_count": str(quorum.approving_count),
                "approving_principal_ids": ",".join(quorum.approving_principal_ids),
                "approval_set_hash": quorum.approval_set_hash,
                "reason": quorum.reason[:200],
            },
        )
        if not quorum.satisfied:
            raise QuorumNotMetError(
                f"approval quorum not met for manifest {manifest_hash}: {quorum.reason}"
            )

        combined_roles = base_role_assignment(
            manifest_hash,
            proposer_id=proposer.principal_id,
            executor_id=subject.principal_id,
            approver_ids=quorum.approving_principal_ids,
        ).merge(role_assignment)
        if separation_policy_bundle is not None:
            self._enforce_separation_of_duty(
                separation_policy_bundle,
                combined_roles,
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=grant_issuer.principal_id,
            )

        if policy_bundle is not None:
            try:
                verify_policy_bundle(policy_bundle, self._ctx.keyring, now=self._ctx.clock.now())
            except KarmaSakshiError:
                self._ctx.audit.record(
                    event_type="policy_bundle.verification_failed",
                    decision="blocked",
                    manifest_id=sealed.manifest.manifest_id,
                    manifest_hash=manifest_hash,
                    actor_id=grant_issuer.principal_id,
                    metadata={"bundle_id": policy_bundle.bundle.bundle_id},
                )
                raise
            self._enforce_policy_tenant(policy_bundle)
        policy_bundle_hash = policy_bundle.seal.bundle_hash if policy_bundle is not None else None

        try:
            grant = issue_grant(
                grant_id=grant_id or str(uuid.uuid4()),
                issuer=grant_issuer,
                subject=subject,
                audience=audience,
                allowed_effect_types=allowed_effect_types,
                scope=scope,
                not_before=not_before,
                expires_at=expires_at,
                nonce=nonce or uuid.uuid4().hex,
                signing_key=signing_key,
                manifest_hash=manifest_hash,
                policy_bundle_hash=policy_bundle_hash,
                approval_set_hash=quorum.approval_set_hash,
                max_uses=max_uses,
                parent_grant_id=parent_grant_id,
                authority_budget_id=authority_budget_id,
                clock=self._ctx.clock,
            )
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="grant.issue_denied",
                decision="blocked",
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=manifest_hash,
                actor_id=grant_issuer.principal_id,
            )
            raise
        self._transition(
            sealed.manifest.manifest_id,
            LifecycleState.AUTHORIZED,
            event_type="grant.issued",
            manifest_hash=manifest_hash,
            grant_id=grant.grant_id,
            actor_id=grant_issuer.principal_id,
            metadata={
                "subject": subject.principal_id,
                "approval_set_hash": quorum.approval_set_hash,
                **({"policy_bundle_hash": policy_bundle_hash} if policy_bundle_hash else {}),
                **_role_participation_metadata(combined_roles),
            },
        )
        return grant

    # --- DELEGATE -----------------------------------------------------------

    def delegate(
        self,
        parent: ExecutionGrant,
        *,
        issuer: Principal,
        subject: Principal,
        signing_key: SigningKey,
        grant_id: str | None = None,
        nonce: str | None = None,
        audience: tuple[str, ...] | None = None,
        allowed_effect_types: tuple[str, ...] | None = None,
        scope: ScopeConstraints | None = None,
        not_before: datetime | None = None,
        expires_at: datetime | None = None,
        max_uses: int | None = None,
        manifest_hash: str | None = None,
        authority_budget_id: str | None = None,
    ) -> ExecutionGrant:
        """Issue a child grant delegated from ``parent``.

        Fields left as ``None`` inherit the parent's exact value (the
        narrowest possible default); pass an explicit, narrower value to
        narrow further. Never returns a grant that would widen authority
        relative to ``parent`` (invariants #15-#18) -- ``issuer`` must be a
        human or service principal, never the agent holding ``parent``
        (invariant #30 applies identically to delegation).
        """
        child = issue_grant(
            grant_id=grant_id or str(uuid.uuid4()),
            issuer=issuer,
            subject=subject,
            audience=audience if audience is not None else parent.audience,
            allowed_effect_types=(
                allowed_effect_types
                if allowed_effect_types is not None
                else parent.allowed_effect_types
            ),
            scope=scope if scope is not None else parent.scope,
            not_before=not_before if not_before is not None else parent.not_before,
            expires_at=expires_at if expires_at is not None else parent.expires_at,
            nonce=nonce or uuid.uuid4().hex,
            signing_key=signing_key,
            manifest_hash=manifest_hash,
            max_uses=max_uses if max_uses is not None else parent.max_uses,
            parent_grant_id=parent.grant_id,
            authority_budget_id=(
                parent.authority_budget_id if authority_budget_id is None else authority_budget_id
            ),
            clock=self._ctx.clock,
        )
        try:
            assert_grant_narrower_or_equal(child, parent)
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="grant.delegation_denied",
                decision="blocked_widening",
                grant_id=child.grant_id,
                actor_id=issuer.principal_id,
                metadata={"parent_grant_id": parent.grant_id},
            )
            raise
        self._ctx.audit.record(
            event_type="grant.delegated",
            decision="allowed",
            grant_id=child.grant_id,
            actor_id=issuer.principal_id,
            metadata={"parent_grant_id": parent.grant_id, "subject": subject.principal_id},
        )
        self._record_grant_lineage(child)
        return child

    # --- COMMIT -----------------------------------------------------------

    def commit(
        self,
        sealed: SealedManifest,
        grant: ExecutionGrant,
        adapter: EffectAdapter,
        context: Any,
        policy_bundle: SealedPolicyBundle | None = None,
        decision_envelope: DecisionEnvelope | None = None,
        causal_graph: CausalEffectGraph | None = None,
    ) -> CommitResult:
        manifest = sealed.manifest
        manifest_id = manifest.manifest_id
        manifest_hash = sealed.seal.manifest_hash
        grant_id = grant.grant_id
        actor_id = manifest.actor.principal_id

        def deny(event_type: str, decision: str, exc: Exception) -> NoReturn:
            self._ctx.audit.record(
                event_type=event_type,
                decision=decision,
                manifest_id=manifest_id,
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
            )
            raise exc

        try:
            # Full cryptographic verification, not just hash-based tamper detection:
            # a manifest whose content is untouched but whose seal signature has been
            # forged or swapped for an untrusted/unknown key must still fail closed.
            verify_seal(sealed, self._ctx.keyring)
        except KarmaSakshiError as exc:
            deny("manifest.seal_verification_failed", f"blocked_{type(exc).__name__}", exc)

        try:
            verify_grant(
                grant,
                self._ctx.keyring,
                now=self._ctx.clock.now(),
                leeway=timedelta(seconds=self._ctx.clock_skew.leeway_seconds),
            )
        except KarmaSakshiError as exc:
            deny("grant.verification_failed", f"blocked_{type(exc).__name__}", exc)

        if grant.manifest_hash != manifest_hash:
            deny(
                "grant.manifest_mismatch",
                "blocked_manifest_mismatch",
                GrantManifestMismatchError(
                    f"grant {grant_id} is bound to a different manifest than the one presented"
                ),
            )

        if grant.policy_bundle_hash is not None:
            # This grant was authorized against a specific signed policy
            # bundle; the exact same bundle (by hash) must be re-verified
            # here, or a policy edit/swap between authorize() and commit()
            # could silently change what was actually approved.
            if policy_bundle is None:
                deny(
                    "policy_bundle.missing_at_commit",
                    "blocked_policy_bundle_missing",
                    PolicyBundleMismatchError(
                        f"grant {grant_id} requires policy bundle "
                        f"{grant.policy_bundle_hash} to be presented at commit time"
                    ),
                )
            else:
                try:
                    verify_policy_bundle(
                        policy_bundle, self._ctx.keyring, now=self._ctx.clock.now()
                    )
                except KarmaSakshiError as exc:
                    deny(
                        "policy_bundle.verification_failed",
                        f"blocked_{type(exc).__name__}",
                        exc,
                    )
                if policy_bundle.seal.bundle_hash != grant.policy_bundle_hash:
                    deny(
                        "policy_bundle.mismatch",
                        "blocked_policy_bundle_mismatch",
                        PolicyBundleMismatchError(
                            f"grant {grant_id} is bound to policy bundle "
                            f"{grant.policy_bundle_hash}, but a different bundle "
                            f"({policy_bundle.seal.bundle_hash}) was presented at commit time"
                        ),
                    )
                try:
                    self._enforce_policy_tenant(policy_bundle)
                except TenantIsolationError as exc:
                    deny(
                        "tenant.policy_isolation",
                        "blocked_tenant_isolation",
                        exc,
                    )
        elif self._ctx.tenant_id is not None and policy_bundle is not None:
            try:
                self._enforce_policy_tenant(policy_bundle)
            except TenantIsolationError as exc:
                deny(
                    "tenant.policy_isolation",
                    "blocked_tenant_isolation",
                    exc,
                )

        if grant.decision_envelope_hash is not None:
            if decision_envelope is None:
                deny(
                    "decision_envelope.missing_at_commit",
                    "blocked_decision_envelope_missing",
                    DecisionEnvelopeMismatchError(
                        f"grant {grant_id} requires decision envelope "
                        f"{grant.decision_envelope_hash} to be presented at commit time"
                    ),
                )
            try:
                verify_decision_envelope(
                    decision_envelope, self._ctx.keyring, now=self._ctx.clock.now()
                )
            except KarmaSakshiError as exc:
                deny(
                    "decision_envelope.verification_failed",
                    f"blocked_{type(exc).__name__}",
                    exc,
                )
            if decision_envelope.canonical_hash() != grant.decision_envelope_hash:
                deny(
                    "decision_envelope.mismatch",
                    "blocked_decision_envelope_mismatch",
                    DecisionEnvelopeMismatchError(
                        f"grant {grant_id} is bound to decision envelope "
                        f"{grant.decision_envelope_hash}, but a different envelope "
                        f"({decision_envelope.canonical_hash()}) was presented at commit time"
                    ),
                )
            try:
                assert_manifest_fits_envelope(manifest, decision_envelope)
            except KarmaSakshiError as exc:
                deny(
                    "decision_envelope.constraint_failed",
                    f"blocked_{type(exc).__name__}",
                    exc,
                )

        if grant.causal_graph_hash is not None:
            if causal_graph is None:
                deny(
                    "atomic_plan.missing_at_commit",
                    "blocked_causal_graph_missing",
                    AtomicPlanError(
                        f"grant {grant_id} requires causal graph "
                        f"{grant.causal_graph_hash} to be presented at commit time"
                    ),
                )
            try:
                require_matching_plan_hash(causal_graph, grant.causal_graph_hash)
                assert_manifest_in_plan(manifest_hash, causal_graph, keyring=self._ctx.keyring)
            except KarmaSakshiError as exc:
                deny(
                    "atomic_plan.verification_failed",
                    f"blocked_{type(exc).__name__}",
                    exc,
                )

        if adapter.adapter_id not in grant.audience:
            deny(
                "grant.audience_mismatch",
                "blocked_adapter_not_in_audience",
                GrantAudienceError(
                    f"adapter {adapter.adapter_id!r} is not within grant audience {grant.audience}"
                ),
            )

        if (
            manifest.adapter.adapter_id != adapter.adapter_id
            or manifest.adapter.adapter_version != adapter.adapter_version
        ):
            deny(
                "adapter.identity_mismatch",
                "blocked_adapter_identity_mismatch",
                AdapterMismatchError(
                    f"manifest was prepared for adapter "
                    f"{manifest.adapter.adapter_id}@{manifest.adapter.adapter_version}, "
                    f"but executing adapter is {adapter.adapter_id}@{adapter.adapter_version}"
                ),
            )

        # Phase 17: when a registry is configured, unknown/revoked adapters and
        # undeclared effect types fail closed before any grant reservation.
        try:
            self._require_trusted_adapter(adapter, effect_type=manifest.effect_type)
        except UntrustedAdapterError as exc:
            deny(
                "adapter.untrusted",
                "blocked_untrusted_adapter",
                exc,
            )

        if manifest.effect_type not in grant.allowed_effect_types:
            deny(
                "grant.effect_type_mismatch",
                "blocked_effect_type_not_permitted",
                GrantAudienceError(
                    f"effect_type {manifest.effect_type!r} not in grant's allowed_effect_types"
                ),
            )

        if self._ctx.grant_store.is_revoked(grant_id):
            deny(
                "grant.revoked",
                "blocked_revoked",
                GrantRevokedError(f"grant {grant_id} is revoked"),
            )

        # Deep ancestor revocation (Phase 11): walk recorded lineage and fail
        # closed on any revoked ancestor, missing intermediate lineage, cycles,
        # or depth overflow. Roots (no parent) are a no-op.
        try:
            ancestors = assert_no_revoked_ancestors(grant, self._ctx.grant_store)
        except (GrantRevokedError, DelegationLineageError) as exc:
            deny(
                "grant.ancestor_revoked"
                if isinstance(exc, GrantRevokedError)
                else "grant.lineage_uncertain",
                "blocked_ancestor_revoked"
                if isinstance(exc, GrantRevokedError)
                else "blocked_lineage_uncertain",
                exc,
            )
        else:
            if ancestors:
                self._ctx.audit.record(
                    event_type="grant.ancestor_revocation_checked",
                    decision="ancestors_clear",
                    manifest_id=manifest_id,
                    manifest_hash=manifest_hash,
                    grant_id=grant_id,
                    actor_id=actor_id,
                    metadata={"ancestor_count": str(len(ancestors))},
                )

        # Phase 12: reserve authority budget before grant use / adapter commit.
        # Idempotent replays release the reservation without consuming.
        budget_id = grant.authority_budget_id
        budget_amount: int | None = None
        if budget_id is not None:
            try:
                budget = require_budget(self._ctx.budget_ledger, budget_id)
                budget_amount = resolve_budget_consume_amount(budget, manifest)
            except AuthorityBudgetError as exc:
                deny(
                    "authority_budget.resolve_failed",
                    f"blocked_{type(exc).__name__}",
                    exc,
                )
            assert self._ctx.budget_ledger is not None  # nosec B101 - require_budget above
            if not self._ctx.budget_ledger.reserve(budget_id, budget_amount):
                deny(
                    "authority_budget.exhausted",
                    "blocked_authority_budget_exhausted",
                    AuthorityBudgetExhaustedError(
                        f"authority budget {budget_id} exhausted for amount={budget_amount} "
                        f"(remaining={self._ctx.budget_ledger.remaining(budget_id)})"
                    ),
                )

        def release_budget() -> None:
            if budget_id is not None and budget_amount is not None and self._ctx.budget_ledger:
                self._ctx.budget_ledger.release(budget_id, budget_amount)

        if not self._ctx.grant_store.reserve(grant_id, grant.max_uses):
            release_budget()
            deny(
                "grant.reservation_failed",
                "blocked_exhausted_or_inflight",
                GrantExhaustedError(
                    f"grant {grant_id} has no available uses "
                    f"(revoked, already in-flight, or max_uses reached)"
                ),
            )

        try:
            self._transition(
                manifest_id,
                LifecycleState.COMMITTING,
                event_type="effect.committing",
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata=(
                    {
                        "authority_budget_id": budget_id,
                        "authority_budget_amount": str(budget_amount),
                    }
                    if budget_id is not None
                    else None
                ),
            )
        except Exception:
            # Audit failure before a consequential commit must block execution
            # (invariant #23) -- but the reservation slot must not leak forever,
            # so release it before propagating.
            self._ctx.grant_store.release(grant_id)
            release_budget()
            raise

        outbox_pending = False
        if self._ctx.outbox_store is not None:
            try:
                self._ctx.outbox_store.record_pending(
                    OutboxEntry(
                        idempotency_key=manifest.idempotency_key,
                        grant_id=grant_id,
                        manifest_id=manifest_id,
                        manifest_hash=manifest_hash,
                        status="pending",
                        created_at=self._ctx.clock.now(),
                    )
                )
                outbox_pending = True
            except (OutboxConflictError, StoreUnavailableError) as exc:
                self._ctx.grant_store.release(grant_id)
                release_budget()
                deny(
                    "outbox.record_failed",
                    f"blocked_{type(exc).__name__}",
                    exc,
                )

        def abandon_outbox() -> None:
            if outbox_pending and self._ctx.outbox_store is not None:
                self._ctx.outbox_store.mark_abandoned(manifest.idempotency_key)

        def confirm_outbox(outcome_ref: str) -> None:
            if self._ctx.outbox_store is not None:
                # Confirm even if we did not just record (idempotent replay path).
                existing = self._ctx.outbox_store.get(manifest.idempotency_key)
                if (existing is not None and existing.status == "pending") or outbox_pending:
                    self._ctx.outbox_store.mark_confirmed(manifest.idempotency_key, outcome_ref)

        existing_outcome = self._ctx.grant_store.get_idempotent_outcome(manifest.idempotency_key)
        if existing_outcome is not None:
            # Already committed effect: finalize grant use, do not consume budget again.
            release_budget()
            confirm_outbox(existing_outcome)
            self._ctx.grant_store.commit(grant_id, manifest.idempotency_key, existing_outcome)
            self._transition(
                manifest_id,
                LifecycleState.COMMITTED,
                event_type="effect.committed_idempotent_replay",
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata={"outcome_ref": existing_outcome},
            )
            return CommitResult(
                success=True,
                idempotency_key=manifest.idempotency_key,
                provider_reference=existing_outcome,
                detail="idempotent replay: effect was already committed for this idempotency key",
            )

        try:
            precondition_result = adapter.validate_preconditions(manifest, context)
        except Exception as exc:
            self._ctx.grant_store.release(grant_id)
            release_budget()
            abandon_outbox()
            self._transition(
                manifest_id,
                LifecycleState.FAILED,
                event_type="effect.precondition_check_error",
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata={"error": str(exc)[:200]},
            )
            raise

        if not precondition_result.satisfied:
            self._ctx.grant_store.release(grant_id)
            release_budget()
            abandon_outbox()
            self._transition(
                manifest_id,
                LifecycleState.FAILED,
                event_type="effect.stale_manifest",
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata={"reason": (precondition_result.reason or "")[:200]},
            )
            raise StaleManifestError(
                precondition_result.reason or "preconditions no longer hold; re-prepare required"
            )

        try:
            commit_result = adapter.commit(manifest, grant, context)
        except Exception as exc:
            self._ctx.grant_store.release(grant_id)
            release_budget()
            # Leave outbox PENDING — outcome may be ambiguous; recovery must re-observe.
            self._transition(
                manifest_id,
                LifecycleState.FAILED,
                event_type="effect.commit_error",
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata={"error": str(exc)[:200], "outbox": "pending_ambiguous"},
            )
            raise

        if not commit_result.success:
            self._ctx.grant_store.release(grant_id)
            release_budget()
            abandon_outbox()
            self._transition(
                manifest_id,
                LifecycleState.FAILED,
                event_type="effect.commit_failed",
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata={"detail": (commit_result.detail or "")[:200]},
            )
            return commit_result

        if budget_id is not None and budget_amount is not None:
            assert self._ctx.budget_ledger is not None  # nosec B101 - reserved above
            self._ctx.budget_ledger.commit(budget_id, budget_amount)
        outcome_ref = commit_result.provider_reference or "committed"
        confirm_outbox(outcome_ref)
        self._ctx.grant_store.commit(grant_id, manifest.idempotency_key, outcome_ref)
        self._transition(
            manifest_id,
            LifecycleState.COMMITTED,
            event_type="effect.committed",
            manifest_hash=manifest_hash,
            grant_id=grant_id,
            actor_id=actor_id,
            metadata={
                "provider_reference": outcome_ref[:200],
                **(
                    {
                        "authority_budget_id": budget_id,
                        "authority_budget_amount": str(budget_amount),
                    }
                    if budget_id is not None
                    else {}
                ),
            },
        )
        return commit_result

    # --- AMBIGUOUS-OUTCOME CRASH RECOVERY --------------------------------------

    def recover_ambiguous_commit(
        self, manifest: EffectManifest, adapter: EffectAdapter, context: Any
    ) -> OutcomeProof:
        """Resolve an ambiguous outcome after a crash between the adapter's
        external effect succeeding and the local store finalizing the
        reservation (see docs/crash-recovery.md).

        This never performs the external effect itself. It asks the adapter
        to independently re-observe external state for
        ``manifest.idempotency_key`` -- exactly the same way :meth:`verify`
        does -- and, if evidence of a prior successful effect is found,
        backfills the idempotency ledger so a subsequent :meth:`commit` call
        takes the fast idempotent-replay path instead of re-invoking the
        adapter. Callers must call this (or otherwise confirm external
        state) before retrying an ambiguous commit; never retry blindly.
        """
        probe = CommitResult(
            success=True,
            idempotency_key=manifest.idempotency_key,
            provider_reference=None,
            detail="ambiguous-outcome recovery probe",
        )
        proof = adapter.verify(manifest, probe, context)
        self._ctx.audit.record(
            event_type="effect.ambiguous_recovery_probe",
            decision="evidence_found" if proof.matched_expected else "no_evidence_found",
            manifest_id=manifest.manifest_id,
            manifest_hash=manifest.canonical_hash(),
            actor_id=manifest.actor.principal_id,
            metadata={"detail": (proof.detail or "")[:200]},
        )
        if proof.matched_expected:
            outcome_ref = proof.observed_after_state_digest or "recovered-externally"
            self._ctx.grant_store.record_idempotent_outcome(manifest.idempotency_key, outcome_ref)
            if self._ctx.outbox_store is not None:
                pending = self._ctx.outbox_store.get(manifest.idempotency_key)
                if pending is not None and pending.status == "pending":
                    self._ctx.outbox_store.mark_confirmed(manifest.idempotency_key, outcome_ref)
        return proof

    def list_pending_outbox(self) -> list[OutboxEntry]:
        """Return pending commit intents when an outbox store is configured."""
        if self._ctx.outbox_store is None:
            return []
        return self._ctx.outbox_store.list_pending()

    # --- VERIFY -----------------------------------------------------------

    def verify(
        self,
        manifest: EffectManifest,
        commit_result: CommitResult,
        adapter: EffectAdapter,
        context: Any,
    ) -> OutcomeProof:
        self._require_trusted_adapter(adapter, effect_type=manifest.effect_type)
        proof = adapter.verify(manifest, commit_result, context)
        self._transition(
            manifest.manifest_id,
            LifecycleState.VERIFIED,
            event_type="effect.verified",
            manifest_hash=manifest.canonical_hash(),
            actor_id=manifest.actor.principal_id,
            metadata={"matched_expected": str(proof.matched_expected)},
        )
        return proof

    # --- WITNESS QUORUM (PROVE-time gate; extreme-v2 Phase 9) ---------------

    def evaluate_witnesses(
        self,
        sealed: SealedManifest,
        *,
        statements: tuple[WitnessStatement, ...] | list[WitnessStatement],
        policy: WitnessPolicy,
        expected_after_state_digest: str,
        actor: Principal,
        subject: Principal,
    ) -> WitnessQuorumResult:
        """Dry-run independent witness quorum evaluation (no raise on miss)."""
        verify_seal(sealed, self._ctx.keyring)
        result = evaluate_witness_quorum(
            statements,
            policy,
            manifest_hash=sealed.seal.manifest_hash,
            expected_after_state_digest=expected_after_state_digest,
            actor=actor,
            subject=subject,
            keyring=self._ctx.keyring,
            now=self._ctx.clock.now(),
        )
        self._ctx.audit.record(
            event_type="witness.quorum_evaluated",
            decision="satisfied" if result.satisfied else "not_satisfied",
            manifest_id=sealed.manifest.manifest_id,
            manifest_hash=sealed.seal.manifest_hash,
            actor_id=actor.principal_id,
            metadata={
                "accepted_count": str(len(result.accepted_witness_ids)),
                "accepted_witness_ids": ",".join(result.accepted_witness_ids),
                "witness_set_hash": result.witness_set_hash or "",
                "witness_policy_hash": result.witness_policy_hash,
                "required_witnesses": str(policy.required_witnesses),
            },
        )
        return result

    def prove_with_witness_quorum(
        self,
        sealed: SealedManifest,
        *,
        statements: tuple[WitnessStatement, ...] | list[WitnessStatement],
        policy: WitnessPolicy,
        expected_after_state_digest: str,
        actor: Principal,
        subject: Principal,
    ) -> WitnessQuorumResult:
        """Assert independent witness quorum for PROVE-time acceptance.

        Does not change the lifecycle state machine (PROVE is the Action
        Passport / evidence surface, not a separate state). Raises
        :class:`WitnessQuorumNotMetError` when unsatisfied.
        """
        result = self.evaluate_witnesses(
            sealed,
            statements=statements,
            policy=policy,
            expected_after_state_digest=expected_after_state_digest,
            actor=actor,
            subject=subject,
        )
        if not result.satisfied:
            reasons = "; ".join(result.rejection_reasons) or "insufficient distinct witnesses"
            raise WitnessQuorumNotMetError(
                f"witness quorum not met for manifest {sealed.seal.manifest_hash}: "
                f"accepted={len(result.accepted_witness_ids)} "
                f"required={policy.required_witnesses}; {reasons}"
            )
        # Re-record assert path distinctly for auditors.
        self._ctx.audit.record(
            event_type="witness.quorum_asserted",
            decision="satisfied",
            manifest_id=sealed.manifest.manifest_id,
            manifest_hash=sealed.seal.manifest_hash,
            actor_id=actor.principal_id,
            metadata={
                "witness_set_hash": result.witness_set_hash or "",
                "witness_policy_hash": result.witness_policy_hash,
            },
        )
        return result

    # --- EVIDENCE QUALITY (VERIFY/PROVE; extreme-v2 Phase 10) ---------------

    def evaluate_evidence(
        self,
        sealed: SealedManifest,
        *,
        records: tuple[EvidenceRecord, ...] | list[EvidenceRecord],
        policy: EvidencePolicy,
        expected_after_state_digest: str | None,
    ) -> EvidenceAssessment:
        """Dry-run evidence quality evaluation (no raise on miss)."""
        verify_seal(sealed, self._ctx.keyring)
        result = evaluate_evidence_quality(
            records,
            policy,
            manifest_hash=sealed.seal.manifest_hash,
            expected_after_state_digest=expected_after_state_digest,
            now=self._ctx.clock.now(),
        )
        self._ctx.audit.record(
            event_type="evidence.quality_evaluated",
            decision="acceptable" if result.acceptable else "rejected",
            manifest_id=sealed.manifest.manifest_id,
            manifest_hash=sealed.seal.manifest_hash,
            actor_id=sealed.manifest.actor.principal_id,
            metadata={
                "accepted_count": str(len(result.accepted_evidence_ids)),
                "evidence_set_hash": result.evidence_set_hash or "",
                "evidence_policy_hash": result.evidence_policy_hash,
                "strongest_kind": (
                    result.strongest_kind.value if result.strongest_kind is not None else ""
                ),
                "min_kind": policy.min_kind.value,
            },
        )
        return result

    def assert_evidence_quality(
        self,
        sealed: SealedManifest,
        *,
        records: tuple[EvidenceRecord, ...] | list[EvidenceRecord],
        policy: EvidencePolicy,
        expected_after_state_digest: str | None,
    ) -> EvidenceAssessment:
        """Assert evidence quality for VERIFY/PROVE acceptance."""
        result = self.evaluate_evidence(
            sealed,
            records=records,
            policy=policy,
            expected_after_state_digest=expected_after_state_digest,
        )
        if not result.acceptable:
            reasons = "; ".join(result.rejection_reasons) or "evidence not acceptable"
            raise EvidenceQualityError(
                f"evidence quality not acceptable for manifest "
                f"{sealed.seal.manifest_hash}: {reasons}"
            )
        self._ctx.audit.record(
            event_type="evidence.quality_asserted",
            decision="acceptable",
            manifest_id=sealed.manifest.manifest_id,
            manifest_hash=sealed.seal.manifest_hash,
            actor_id=sealed.manifest.actor.principal_id,
            metadata={
                "evidence_set_hash": result.evidence_set_hash or "",
                "evidence_policy_hash": result.evidence_policy_hash,
            },
        )
        return result

    # --- COMPENSATE ---------------------------------------------------------

    def authorize_compensation(
        self,
        original_sealed: SealedManifest,
        compensation_sealed: SealedManifest,
        *,
        issuer: Principal,
        subject: Principal,
        audience: tuple[str, ...],
        allowed_effect_types: tuple[str, ...],
        scope: ScopeConstraints,
        not_before: datetime,
        expires_at: datetime,
        signing_key: SigningKey,
        grant_id: str | None = None,
        nonce: str | None = None,
        max_uses: int = 1,
        policy_bundle: SealedPolicyBundle | None = None,
        separation_policy_bundle: SealedPolicyBundle | None = None,
        role_assignment: RoleAssignment | None = None,
    ) -> ExecutionGrant:
        """Authorize a compensation effect that is bound to ``original_sealed``.

        The compensation sealed manifest must bind ``original_manifest_hash``
        (see ``compensation.build_compensation_manifest``). Issues a normal
        grant against the *compensation* manifest hash — never reuses the
        original effect's grant.
        """
        verify_seal(original_sealed, self._ctx.keyring)
        verify_seal(compensation_sealed, self._ctx.keyring)
        try:
            assert_compensation_binds_original(compensation_sealed, original_sealed)
        except KarmaSakshiError:
            self._ctx.audit.record(
                event_type="compensation.binding_failed",
                decision="blocked",
                manifest_id=compensation_sealed.manifest.manifest_id,
                manifest_hash=compensation_sealed.seal.manifest_hash,
                actor_id=issuer.principal_id,
                metadata={"original_manifest_id": original_sealed.manifest.manifest_id},
            )
            raise
        return self.authorize(
            compensation_sealed,
            issuer=issuer,
            subject=subject,
            audience=audience,
            allowed_effect_types=allowed_effect_types,
            scope=scope,
            not_before=not_before,
            expires_at=expires_at,
            signing_key=signing_key,
            grant_id=grant_id,
            nonce=nonce,
            max_uses=max_uses,
            policy_bundle=policy_bundle,
            separation_policy_bundle=separation_policy_bundle,
            role_assignment=role_assignment,
        )

    def commit_compensation(
        self,
        original_sealed: SealedManifest,
        compensation_sealed: SealedManifest,
        grant: ExecutionGrant,
        adapter: EffectAdapter,
        context: Any,
        *,
        original_commit: CommitResult,
        policy_bundle: SealedPolicyBundle | None = None,
    ) -> CommitResult:
        """Commit an authorized compensation effect via ``adapter.compensate``.

        The compensation sealed manifest + grant prove separate authorization.
        Execution calls ``adapter.compensate`` on the *original* effect (never
        ``adapter.commit`` on the compensation manifest), because reference
        adapters reverse effects through ``compensate``, not a second forward
        commit. Does not mutate any Action Passport artifact.

        Returns a :class:`CommitResult` whose ``success`` mirrors
        ``CompensationResult.succeeded`` (attempted-but-failed is
        ``success=False``; refused compensation is also ``success=False``
        with detail explaining refusal).
        """
        verify_seal(original_sealed, self._ctx.keyring)
        try:
            assert_compensation_binds_original(compensation_sealed, original_sealed)
        except CompensationBindingError:
            self._ctx.audit.record(
                event_type="compensation.binding_failed_at_commit",
                decision="blocked",
                manifest_id=compensation_sealed.manifest.manifest_id,
                manifest_hash=compensation_sealed.seal.manifest_hash,
                grant_id=grant.grant_id,
                actor_id=compensation_sealed.manifest.actor.principal_id,
            )
            raise

        # Reuse the full grant/seal gate of commit() against the compensation
        # sealed artifact, but stop before adapter.commit by verifying then
        # consuming the grant around adapter.compensate instead.
        compensation = compensation_sealed.manifest
        compensation_id = compensation.manifest_id
        compensation_hash = compensation_sealed.seal.manifest_hash
        grant_id = grant.grant_id
        actor_id = compensation.actor.principal_id

        def deny(event_type: str, decision: str, exc: Exception) -> NoReturn:
            self._ctx.audit.record(
                event_type=event_type,
                decision=decision,
                manifest_id=compensation_id,
                manifest_hash=compensation_hash,
                grant_id=grant_id,
                actor_id=actor_id,
            )
            raise exc

        try:
            verify_seal(compensation_sealed, self._ctx.keyring)
            verify_grant(
                grant,
                self._ctx.keyring,
                now=self._ctx.clock.now(),
                leeway=timedelta(seconds=self._ctx.clock_skew.leeway_seconds),
            )
        except KarmaSakshiError as exc:
            deny("compensation.verification_failed", f"blocked_{type(exc).__name__}", exc)

        if grant.manifest_hash != compensation_hash:
            deny(
                "compensation.grant_manifest_mismatch",
                "blocked_manifest_mismatch",
                GrantManifestMismatchError(
                    f"grant {grant_id} is bound to a different compensation manifest"
                ),
            )
        if grant.policy_bundle_hash is not None:
            if policy_bundle is None:
                deny(
                    "policy_bundle.missing_at_commit",
                    "blocked_policy_bundle_missing",
                    PolicyBundleMismatchError(
                        f"grant {grant_id} requires policy bundle "
                        f"{grant.policy_bundle_hash} at compensation commit"
                    ),
                )
            else:
                try:
                    verify_policy_bundle(
                        policy_bundle, self._ctx.keyring, now=self._ctx.clock.now()
                    )
                except KarmaSakshiError as exc:
                    deny(
                        "policy_bundle.verification_failed",
                        f"blocked_{type(exc).__name__}",
                        exc,
                    )
                if policy_bundle.seal.bundle_hash != grant.policy_bundle_hash:
                    deny(
                        "policy_bundle.mismatch",
                        "blocked_policy_bundle_mismatch",
                        PolicyBundleMismatchError(
                            f"grant {grant_id} is bound to policy bundle "
                            f"{grant.policy_bundle_hash}, but a different bundle was presented"
                        ),
                    )
        if adapter.adapter_id not in grant.audience:
            deny(
                "grant.audience_mismatch",
                "blocked_adapter_not_in_audience",
                GrantAudienceError(
                    f"adapter {adapter.adapter_id!r} is not in grant audience {grant.audience!r}"
                ),
            )
        if (
            original_sealed.manifest.adapter.adapter_id != adapter.adapter_id
            or original_sealed.manifest.adapter.adapter_version != adapter.adapter_version
        ):
            deny(
                "adapter.identity_mismatch",
                "blocked_adapter_identity_mismatch",
                AdapterMismatchError(
                    "compensation adapter identity does not match the original effect's adapter"
                ),
            )
        # Trust the adapter identity; compensation effect_type uses the
        # ``.compensate`` suffix convention and is separately grant-bound.
        try:
            self._require_trusted_adapter(adapter)
        except UntrustedAdapterError as exc:
            deny(
                "adapter.untrusted",
                "blocked_untrusted_adapter",
                exc,
            )
        if compensation.effect_type not in grant.allowed_effect_types:
            deny(
                "grant.effect_type_mismatch",
                "blocked_effect_type_not_permitted",
                GrantAudienceError(
                    f"effect_type {compensation.effect_type!r} not in grant's allowed_effect_types"
                ),
            )
        if self._ctx.grant_store.is_revoked(grant_id):
            deny(
                "grant.revoked",
                "blocked_revoked",
                GrantRevokedError(f"grant {grant_id} is revoked"),
            )
        if not self._ctx.grant_store.reserve(grant_id, grant.max_uses):
            deny(
                "grant.reservation_failed",
                "blocked_exhausted_or_inflight",
                GrantExhaustedError(f"grant {grant_id} has no available uses"),
            )

        original_state = self.get_lifecycle_state(original_sealed.manifest.manifest_id)
        if original_state == LifecycleState.VERIFIED:
            try:
                self._transition(
                    original_sealed.manifest.manifest_id,
                    LifecycleState.COMPENSATING,
                    event_type="effect.compensating_authorized",
                    manifest_hash=original_sealed.seal.manifest_hash,
                    grant_id=grant_id,
                    actor_id=actor_id,
                    metadata={
                        "compensation_manifest_id": compensation_id,
                        "compensation_manifest_hash": compensation_hash,
                    },
                )
            except Exception:
                self._ctx.grant_store.release(grant_id)
                raise

        try:
            self._transition(
                compensation_id,
                LifecycleState.COMMITTING,
                event_type="compensation.committing",
                manifest_hash=compensation_hash,
                grant_id=grant_id,
                actor_id=actor_id,
            )
            compensation_result = adapter.compensate(
                original_sealed.manifest, original_commit, context
            )
            outcome_ref = (
                f"compensation:{compensation_id}:"
                f"{'ok' if compensation_result.succeeded else 'fail'}"
            )
            self._ctx.grant_store.commit(grant_id, compensation.idempotency_key, outcome_ref)
        except Exception as exc:
            self._ctx.grant_store.release(grant_id)
            self._transition(
                compensation_id,
                LifecycleState.FAILED,
                event_type="compensation.commit_error",
                manifest_hash=compensation_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata={"error": type(exc).__name__},
            )
            raise

        self._transition(
            compensation_id,
            LifecycleState.COMMITTED if compensation_result.succeeded else LifecycleState.FAILED,
            event_type="compensation.commit_result",
            manifest_hash=compensation_hash,
            grant_id=grant_id,
            actor_id=actor_id,
            metadata={
                "attempted": str(compensation_result.attempted),
                "succeeded": str(compensation_result.succeeded),
                "reason": (compensation_result.reason or "")[:200],
            },
        )
        if compensation_result.succeeded:
            self._transition(
                original_sealed.manifest.manifest_id,
                LifecycleState.COMPENSATED,
                event_type="effect.compensation_committed",
                manifest_hash=original_sealed.seal.manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata={
                    "compensation_manifest_id": compensation_id,
                    "provider_reference": outcome_ref,
                },
            )
        elif original_state == LifecycleState.VERIFIED:
            # Authorized attempt that did not succeed: leave original in
            # COMPENSATING/FAILED honestly rather than claiming COMPENSATED.
            self._transition(
                original_sealed.manifest.manifest_id,
                LifecycleState.FAILED,
                event_type="effect.compensation_failed",
                manifest_hash=original_sealed.seal.manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata={
                    "compensation_manifest_id": compensation_id,
                    "attempted": str(compensation_result.attempted),
                    "reason": (compensation_result.reason or "")[:200],
                },
            )

        return CommitResult(
            success=compensation_result.succeeded,
            idempotency_key=compensation.idempotency_key,
            provider_reference=outcome_ref,
            detail=compensation_result.reason or compensation_result.detail,
        )

    def compensate(
        self,
        manifest: EffectManifest,
        commit_result: CommitResult,
        adapter: EffectAdapter,
        context: Any,
    ) -> CompensationResult:
        """Legacy best-effort compensation path (v0.1).

        Still calls ``adapter.compensate`` directly without a separate
        sealed compensation grant. Prefer
        :meth:`authorize_compensation` / :meth:`commit_compensation` for
        the Phase 7 authorized path. This method never builds or mutates
        an Action Passport.
        """
        self._require_trusted_adapter(adapter, effect_type=manifest.effect_type)
        manifest_hash = manifest.canonical_hash()
        self._transition(
            manifest.manifest_id,
            LifecycleState.COMPENSATING,
            event_type="effect.compensating",
            manifest_hash=manifest_hash,
            actor_id=manifest.actor.principal_id,
        )
        result = adapter.compensate(manifest, commit_result, context)
        target = LifecycleState.COMPENSATED if result.succeeded else LifecycleState.FAILED
        self._transition(
            manifest.manifest_id,
            target,
            event_type="effect.compensation_result",
            manifest_hash=manifest_hash,
            actor_id=manifest.actor.principal_id,
            metadata={
                "attempted": str(result.attempted),
                "succeeded": str(result.succeeded),
                "reason": (result.reason or "")[:200],
                "legacy_path": "true",
            },
        )
        return result

    # --- REVOKE -------------------------------------------------------------

    def revoke(self, grant: ExecutionGrant, manifest_id: str, *, revoked_by: Principal) -> bool:
        """Revoke a grant. Always marks it unusable for future reservations.

        Returns ``True`` if the manifest's lifecycle was still at a safe
        checkpoint and was transitioned to REVOKED; ``False`` if execution
        had already progressed past the point where revocation can stop it
        (invariants #26, #27) -- the grant is still marked revoked so it
        cannot be used again, but any already-committed effect is untouched.
        """
        self._ctx.grant_store.revoke(grant.grant_id)
        record = self._get_record(manifest_id)
        if is_revocable(record.state):
            self._transition(
                manifest_id,
                LifecycleState.REVOKED,
                event_type="grant.revoked",
                grant_id=grant.grant_id,
                actor_id=revoked_by.principal_id,
            )
            return True
        self._ctx.audit.record(
            event_type="grant.revoke_requested_past_safepoint",
            decision="grant_marked_revoked_effect_unaffected",
            manifest_id=manifest_id,
            grant_id=grant.grant_id,
            actor_id=revoked_by.principal_id,
            from_state=record.state.value,
            to_state=record.state.value,
        )
        return False

    # --- SAGA ORCHESTRATION (Phase 8) ----------------------------------------

    def get_saga(self, run_id: str) -> SagaRun:
        run = self._saga_runs.get(run_id)
        if run is None:
            raise SagaIllegalTransitionError(f"unknown saga run {run_id!r}")
        return run

    def begin_saga(
        self,
        graph: CausalEffectGraph,
        *,
        saga_id: str | None = None,
        run_id: str | None = None,
        actor_id: str | None = None,
    ) -> SagaRun:
        """Create a deterministic saga run over a verified causal graph.

        Does not issue grants or execute effects. Each step still requires
        its own sealed manifest + grant (typically via :meth:`authorize_plan`).
        """
        graph.verify(self._ctx.keyring)
        plan = build_saga_plan(graph, saga_id=saga_id, clock=self._ctx.clock)
        if plan.causal_graph_hash != graph.canonical_hash():
            raise SagaGraphMismatchError("saga plan graph hash mismatch")
        run = build_saga_run(plan, run_id=run_id)
        run = run.model_copy(update={"status": SagaRunStatus.RUNNING})
        self._saga_runs[run.run_id] = run
        self._ctx.audit.record(
            event_type="saga.begun",
            decision="started",
            actor_id=actor_id,
            metadata={
                "run_id": run.run_id,
                "saga_id": plan.saga_id,
                "plan_hash": plan.canonical_hash(),
                "causal_graph_hash": plan.causal_graph_hash,
                "steps": str(len(plan.step_manifest_hashes)),
            },
        )
        return run

    def authorize_saga_step(
        self,
        run_id: str,
        sealed: SealedManifest,
        graph: CausalEffectGraph,
        *,
        issuer: Principal,
        subject: Principal,
        audience: tuple[str, ...],
        allowed_effect_types: tuple[str, ...],
        scope: ScopeConstraints,
        not_before: datetime,
        expires_at: datetime,
        signing_key: SigningKey,
        grant_id: str | None = None,
        nonce: str | None = None,
        max_uses: int = 1,
        policy_bundle: SealedPolicyBundle | None = None,
        separation_policy_bundle: SealedPolicyBundle | None = None,
        role_assignment: RoleAssignment | None = None,
    ) -> ExecutionGrant:
        run = self.get_saga(run_id)
        if graph.canonical_hash() != run.plan.causal_graph_hash:
            raise SagaGraphMismatchError(
                "presented causal graph does not match the saga plan binding"
            )
        manifest_hash = sealed.seal.manifest_hash
        grant = self.authorize_plan(
            sealed,
            graph,
            issuer=issuer,
            subject=subject,
            audience=audience,
            allowed_effect_types=allowed_effect_types,
            scope=scope,
            not_before=not_before,
            expires_at=expires_at,
            signing_key=signing_key,
            grant_id=grant_id,
            nonce=nonce,
            max_uses=max_uses,
            policy_bundle=policy_bundle,
            separation_policy_bundle=separation_policy_bundle,
            role_assignment=role_assignment,
        )
        updated = mark_step_authorized(run, manifest_hash, grant.grant_id)
        self._saga_runs[run_id] = updated
        self._ctx.audit.record(
            event_type="saga.step_authorized",
            decision="allowed",
            grant_id=grant.grant_id,
            manifest_hash=manifest_hash,
            actor_id=issuer.principal_id,
            metadata={"run_id": run_id, "cursor": str(updated.cursor)},
        )
        return grant

    def commit_saga_step(
        self,
        run_id: str,
        sealed: SealedManifest,
        grant: ExecutionGrant,
        adapter: EffectAdapter,
        context: Any,
        *,
        causal_graph: CausalEffectGraph,
        policy_bundle: SealedPolicyBundle | None = None,
        ambiguous: bool = False,
    ) -> CommitResult:
        """Commit the current saga cursor step (at-most-once).

        If ``ambiguous=True``, records AMBIGUOUS without calling the adapter
        (caller detected an indeterminate prior attempt). Otherwise calls
        :meth:`commit`. Blind re-commit of AMBIGUOUS steps is refused.
        """
        run = self.get_saga(run_id)
        if causal_graph.canonical_hash() != run.plan.causal_graph_hash:
            raise SagaGraphMismatchError(
                "presented causal graph does not match the saga plan binding"
            )
        manifest_hash = sealed.seal.manifest_hash
        assert_can_commit_step(run, manifest_hash)
        if sealed.seal.manifest_hash not in set(run.plan.step_manifest_hashes):
            raise SagaIllegalTransitionError("manifest is not a node of this saga plan")
        if ambiguous:
            updated = mark_step_ambiguous(run, manifest_hash, detail="caller reported ambiguous")
            self._saga_runs[run_id] = updated
            self._ctx.audit.record(
                event_type="saga.step_ambiguous",
                decision="awaiting_recovery",
                manifest_hash=manifest_hash,
                grant_id=grant.grant_id,
                metadata={"run_id": run_id},
            )
            raise SagaAmbiguousStepError(
                f"saga step {manifest_hash} marked AMBIGUOUS; recover before continuing"
            )
        try:
            result = self.commit(
                sealed,
                grant,
                adapter,
                context,
                policy_bundle=policy_bundle,
                causal_graph=causal_graph,
            )
        except Exception as exc:
            # Fail closed for security denials; treat unexpected adapter
            # failures as step failure that starts compensation of prior steps.
            if isinstance(exc, KarmaSakshiError) and not isinstance(exc, StaleManifestError):
                raise
            updated = mark_step_failed(run, manifest_hash, detail=str(exc))
            self._saga_runs[run_id] = updated
            self._ctx.audit.record(
                event_type="saga.step_failed",
                decision=(
                    "compensating" if updated.status == SagaRunStatus.COMPENSATING else "aborted"
                ),
                manifest_hash=manifest_hash,
                metadata={"run_id": run_id, "error": type(exc).__name__},
            )
            raise
        if not result.success:
            updated = mark_step_failed(run, manifest_hash, detail=result.detail)
        else:
            updated = mark_step_committed(
                run,
                manifest_hash,
                success=True,
                provider_reference=result.provider_reference,
                detail=result.detail,
            )
        self._saga_runs[run_id] = updated
        self._ctx.audit.record(
            event_type="saga.step_committed",
            decision="success" if result.success else "failed",
            manifest_hash=manifest_hash,
            grant_id=grant.grant_id,
            metadata={
                "run_id": run_id,
                "provider_reference": result.provider_reference or "",
                "saga_status": updated.status.value,
            },
        )
        return result

    def verify_saga_step(
        self,
        run_id: str,
        sealed: SealedManifest,
        commit_result: CommitResult,
        adapter: EffectAdapter,
        context: Any,
    ) -> OutcomeProof:
        run = self.get_saga(run_id)
        proof = self.verify(sealed.manifest, commit_result, adapter, context)
        if proof.matched_expected:
            updated = mark_step_verified(run, sealed.seal.manifest_hash)
            self._saga_runs[run_id] = updated
            self._ctx.audit.record(
                event_type="saga.step_verified",
                decision="matched",
                manifest_hash=sealed.seal.manifest_hash,
                metadata={"run_id": run_id, "saga_status": updated.status.value},
            )
        return proof

    def recover_saga_step(
        self,
        run_id: str,
        sealed: SealedManifest,
        adapter: EffectAdapter,
        context: Any,
    ) -> OutcomeProof:
        run = self.get_saga(run_id)
        manifest_hash = sealed.seal.manifest_hash
        assert_can_recover_step(run, manifest_hash)
        proof = self.recover_ambiguous_commit(sealed.manifest, adapter, context)
        if proof.matched_expected:
            updated = mark_step_committed(
                run.model_copy(
                    update={
                        "status": SagaRunStatus.RUNNING,
                        "steps": tuple(
                            s.model_copy(
                                update={
                                    "status": SagaStepStatus.AUTHORIZED,
                                    "ambiguous": False,
                                }
                            )
                            if s.manifest_hash == manifest_hash
                            else s
                            for s in run.steps
                        ),
                    }
                ),
                manifest_hash,
                success=True,
                provider_reference=proof.observed_after_state_digest,
                detail=proof.detail,
            )
        else:
            updated = mark_step_failed(run, manifest_hash, detail=proof.detail)
        self._saga_runs[run_id] = updated
        self._ctx.audit.record(
            event_type="saga.step_recovered",
            decision="evidence_found" if proof.matched_expected else "no_evidence",
            manifest_hash=manifest_hash,
            metadata={"run_id": run_id, "saga_status": updated.status.value},
        )
        return proof

    def record_saga_compensation(
        self,
        run_id: str,
        original_manifest_hash: str,
        status: CompensationStatus,
        *,
        detail: str | None = None,
    ) -> SagaRun:
        """Record a Phase 7 compensation outcome for the current reverse cursor."""
        run = self.get_saga(run_id)
        expected = next_compensation_manifest_hash(run)
        if expected != original_manifest_hash:
            raise SagaIllegalTransitionError(
                f"compensation cursor expects {expected}, got {original_manifest_hash}"
            )
        updated = mark_compensation_result(run, original_manifest_hash, status, detail=detail)
        self._saga_runs[run_id] = updated
        self._ctx.audit.record(
            event_type="saga.compensation_recorded",
            decision=status.value,
            manifest_hash=original_manifest_hash,
            metadata={
                "run_id": run_id,
                "saga_status": updated.status.value,
                "step_status": next(
                    s.status.value
                    for s in updated.steps
                    if s.manifest_hash == original_manifest_hash
                ),
            },
        )
        return updated


__all__ = ["KarmaSakshiEngine"]
