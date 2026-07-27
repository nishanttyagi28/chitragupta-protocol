"""The core engine: orchestrates PROPOSE -> PREPARE -> SEAL -> AUTHORIZE ->
COMMIT -> VERIFY, delegating the external effect to an :class:`EffectAdapter`
while owning every security decision itself (invariant #30: the adapter/agent
never decides authorization).

See docs/architecture.md for the full sequence diagram.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, NoReturn

from chitragupta.adapters.base import (
    CommitResult,
    CompensationResult,
    EffectAdapter,
    OutcomeProof,
)
from chitragupta.crypto.keys import SigningKey
from chitragupta.delegation.attenuation import assert_grant_narrower_or_equal
from chitragupta.domain.common import Principal
from chitragupta.domain.manifest import EffectManifest
from chitragupta.domain.seal import SealedManifest
from chitragupta.engine.context import EngineContext
from chitragupta.errors import (
    AdapterMismatchError,
    ChitraguptaError,
    GrantAudienceError,
    GrantExhaustedError,
    GrantManifestMismatchError,
    GrantRevokedError,
    StaleManifestError,
)
from chitragupta.grants.issuer import issue_grant
from chitragupta.grants.model import ExecutionGrant, ScopeConstraints
from chitragupta.grants.verifier import verify_grant
from chitragupta.protocol.sealing import seal_manifest, verify_seal
from chitragupta.state_machine.record import LifecycleRecord
from chitragupta.state_machine.states import LifecycleState, is_revocable


class ChitraguptaEngine:
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
        except ChitraguptaError:
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
    ) -> ExecutionGrant:
        verify_seal(sealed, self._ctx.keyring)
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
                manifest_hash=sealed.seal.manifest_hash,
                max_uses=max_uses,
                parent_grant_id=parent_grant_id,
                clock=self._ctx.clock,
            )
        except ChitraguptaError:
            self._ctx.audit.record(
                event_type="grant.issue_denied",
                decision="blocked",
                manifest_id=sealed.manifest.manifest_id,
                manifest_hash=sealed.seal.manifest_hash,
                actor_id=issuer.principal_id,
            )
            raise
        self._transition(
            sealed.manifest.manifest_id,
            LifecycleState.AUTHORIZED,
            event_type="grant.issued",
            manifest_hash=sealed.seal.manifest_hash,
            grant_id=grant.grant_id,
            actor_id=issuer.principal_id,
            metadata={"subject": subject.principal_id},
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
        except ChitraguptaError:
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
            sealed.verify_integrity()
        except ChitraguptaError as exc:
            deny("manifest.tamper_detected", "blocked_tampered_manifest", exc)

        try:
            verify_grant(
                grant,
                self._ctx.keyring,
                now=self._ctx.clock.now(),
                leeway=timedelta(seconds=self._ctx.clock_skew.leeway_seconds),
            )
        except ChitraguptaError as exc:
            deny("grant.verification_failed", f"blocked_{type(exc).__name__}", exc)

        if grant.manifest_hash != manifest_hash:
            deny(
                "grant.manifest_mismatch",
                "blocked_manifest_mismatch",
                GrantManifestMismatchError(
                    f"grant {grant_id} is bound to a different manifest than the one presented"
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
            # chitragupta.delegation.verify_delegation_chain with the full chain of
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

        self._transition(
            manifest_id,
            LifecycleState.COMMITTING,
            event_type="effect.committing",
            manifest_hash=manifest_hash,
            grant_id=grant_id,
            actor_id=actor_id,
        )

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


__all__ = ["ChitraguptaEngine"]
