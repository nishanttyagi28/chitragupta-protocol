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
from karmasakshi.crypto.keys import SigningKey
from karmasakshi.delegation.attenuation import assert_grant_narrower_or_equal
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
from karmasakshi.errors import (
    AdapterMismatchError,
    GrantAudienceError,
    GrantExhaustedError,
    GrantManifestMismatchError,
    GrantRevokedError,
    KarmaSakshiError,
    PolicyBundleMismatchError,
    QuorumNotMetError,
    SeparationOfDutyViolationError,
    StaleManifestError,
)
from karmasakshi.grants.issuer import issue_grant
from karmasakshi.grants.model import ExecutionGrant, ScopeConstraints
from karmasakshi.grants.verifier import verify_grant
from karmasakshi.intelligence.facts import AssessmentFacts
from karmasakshi.intelligence.model import EffectAssessment
from karmasakshi.policy.bundle import SealedPolicyBundle
from karmasakshi.policy.sealing import verify_policy_bundle
from karmasakshi.protocol.sealing import seal_manifest, verify_seal
from karmasakshi.state_machine.record import LifecycleRecord
from karmasakshi.state_machine.states import LifecycleState, is_revocable


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

    @property
    def context(self) -> EngineContext:
        return self._ctx

    def get_lifecycle_state(self, manifest_id: str) -> LifecycleState:
        return self._get_record(manifest_id).state

    def seed_lifecycle_state(self, manifest_id: str, state: LifecycleState) -> None:
        """Seed the in-memory lifecycle record for ``manifest_id`` to ``state``
        without performing a transition or writing an audit event.

        This engine's lifecycle records are process-local; the durable
        record of what actually happened lives in the audit journal. A
        long-running host that reconstructs a fresh engine per invocation
        (the CLI, in particular) uses this to restore the correct starting
        state from the audit journal before continuing the lifecycle --
        never to fabricate a state that didn't actually happen.
        """
        self._records[manifest_id] = LifecycleRecord(manifest_id=manifest_id, state=state)

    def _get_record(self, manifest_id: str) -> LifecycleRecord:
        record = self._records.get(manifest_id)
        if record is None:
            record = LifecycleRecord(manifest_id=manifest_id)
            self._records[manifest_id] = record
        return record

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

    # --- PREPARE --------------------------------------------------------------

    def prepare(self, adapter: EffectAdapter, request: Any, context: Any) -> EffectManifest:
        manifest = adapter.prepare(request, context)
        self._transition(
            manifest.manifest_id,
            LifecycleState.PREPARED,
            event_type="manifest.prepared",
            manifest_hash=manifest.canonical_hash(),
            actor_id=manifest.actor.principal_id,
            metadata={"adapter_id": adapter.adapter_id, "effect_type": manifest.effect_type},
        )
        return manifest

    # --- ASSESS -------------------------------------------------------------

    def assess(
        self,
        manifest: EffectManifest,
        facts: AssessmentFacts | None = None,
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
        """
        assessment = self._ctx.intelligence.assess(manifest, facts)
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
        """
        verify_seal(sealed, self._ctx.keyring)
        manifest_hash = sealed.seal.manifest_hash
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
        return child

    # --- COMMIT -----------------------------------------------------------

    def commit(
        self,
        sealed: SealedManifest,
        grant: ExecutionGrant,
        adapter: EffectAdapter,
        context: Any,
        policy_bundle: SealedPolicyBundle | None = None,
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

        if grant.parent_grant_id is not None and self._ctx.grant_store.is_revoked(
            grant.parent_grant_id
        ):
            # One-hop revocation propagation: if the immediate parent capability was
            # revoked, this delegated grant cannot be used even though it was never
            # itself revoked. Deeper ancestor chains must be checked explicitly via
            # karmasakshi.delegation.verify_delegation_chain with the full chain of
            # grant objects -- the store only tracks revocation by grant_id, not
            # full lineage, so we cannot walk further than one hop from here alone.
            deny(
                "grant.parent_revoked",
                "blocked_parent_revoked",
                GrantRevokedError(
                    f"grant {grant_id}'s parent grant {grant.parent_grant_id} is revoked"
                ),
            )

        if not self._ctx.grant_store.reserve(grant_id, grant.max_uses):
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
            )
        except Exception:
            # Audit failure before a consequential commit must block execution
            # (invariant #23) -- but the reservation slot must not leak forever,
            # so release it before propagating.
            self._ctx.grant_store.release(grant_id)
            raise

        existing_outcome = self._ctx.grant_store.get_idempotent_outcome(manifest.idempotency_key)
        if existing_outcome is not None:
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
            self._transition(
                manifest_id,
                LifecycleState.FAILED,
                event_type="effect.commit_error",
                manifest_hash=manifest_hash,
                grant_id=grant_id,
                actor_id=actor_id,
                metadata={"error": str(exc)[:200]},
            )
            raise

        if not commit_result.success:
            self._ctx.grant_store.release(grant_id)
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

        self._ctx.grant_store.commit(
            grant_id, manifest.idempotency_key, commit_result.provider_reference or "committed"
        )
        self._transition(
            manifest_id,
            LifecycleState.COMMITTED,
            event_type="effect.committed",
            manifest_hash=manifest_hash,
            grant_id=grant_id,
            actor_id=actor_id,
            metadata={"provider_reference": (commit_result.provider_reference or "")[:200]},
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
        return proof

    # --- VERIFY -----------------------------------------------------------

    def verify(
        self,
        manifest: EffectManifest,
        commit_result: CommitResult,
        adapter: EffectAdapter,
        context: Any,
    ) -> OutcomeProof:
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

    # --- COMPENSATE ---------------------------------------------------------

    def compensate(
        self,
        manifest: EffectManifest,
        commit_result: CommitResult,
        adapter: EffectAdapter,
        context: Any,
    ) -> CompensationResult:
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


__all__ = ["KarmaSakshiEngine"]
