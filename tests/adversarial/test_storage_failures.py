"""Fail-closed behavior when storage (grant store / audit journal) is
unavailable or returns indeterminate results.

Invariant #10: store outages or indeterminate authorization states fail
closed. Invariant #23: audit failure before a consequential commit blocks
execution.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.errors import AuditWriteError, StoreUnavailableError
from karmasakshi.grants.model import ScopeConstraints


class _ExplodingGrantStore:
    """A GrantStore stand-in where every method raises, simulating a
    completely unreachable backend (network partition, dead database)."""

    def reserve(self, grant_id, max_uses):
        raise StoreUnavailableError("simulated store outage")

    def release(self, grant_id):
        raise StoreUnavailableError("simulated store outage")

    def commit(self, grant_id, idempotency_key, outcome_ref):
        raise StoreUnavailableError("simulated store outage")

    def revoke(self, grant_id):
        raise StoreUnavailableError("simulated store outage")

    def is_revoked(self, grant_id):
        raise StoreUnavailableError("simulated store outage")

    def get_use_count(self, grant_id):
        raise StoreUnavailableError("simulated store outage")

    def get_idempotent_outcome(self, idempotency_key):
        raise StoreUnavailableError("simulated store outage")

    def record_idempotent_outcome(self, idempotency_key, outcome_ref):
        raise StoreUnavailableError("simulated store outage")


class _FailingAuditBackend:
    def append(self, event):
        raise RuntimeError("simulated disk full")

    def all_events(self):
        return []

    def last_event(self):
        return None


def _authorize(engine, sealed, *, issuer, subject, issuer_signing_key, now):
    return engine.authorize(
        sealed,
        issuer=issuer,
        subject=subject,
        audience=("payment.simulator",),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )


def test_store_outage_at_revocation_check_fails_closed(
    engine_factory,
    manifest_factory,
    fake_adapter,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory(grant_store=_ExplodingGrantStore())
    manifest = manifest_factory()
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )
    with pytest.raises(StoreUnavailableError):
        engine.commit(sealed, grant, fake_adapter, context=None)


def test_audit_backend_failure_blocks_commit_before_adapter_is_called(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    from karmasakshi.audit.journal import AuditJournal
    from karmasakshi.config.clock import FixedClock
    from karmasakshi.engine import EngineContext, KarmaSakshiEngine
    from karmasakshi.stores.memory import InMemoryGrantStore

    keyring = engine_factory().context.keyring
    clock = FixedClock(now)
    good_engine = KarmaSakshiEngine(
        EngineContext(
            keyring=keyring,
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=clock),
            clock=clock,
        )
    )
    manifest = manifest_factory()
    prepared = good_engine.prepare(fake_adapter, manifest, context=None)
    sealed = good_engine.seal(prepared, issuer_signing_key)
    grant = _authorize(
        good_engine,
        sealed,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )

    # Swap in a failing audit backend right before commit, simulating an
    # audit sink that goes down between authorization and execution.
    failing_engine = KarmaSakshiEngine(
        EngineContext(
            keyring=keyring,
            grant_store=good_engine.context.grant_store,
            audit=AuditJournal(backend=_FailingAuditBackend(), clock=clock),
            clock=clock,
        )
    )
    with pytest.raises(AuditWriteError):
        failing_engine.commit(sealed, grant, fake_adapter, context=None)

    # The external effect must never have been attempted.
    assert fake_adapter_state.committed == []
    # The reservation must not leak: a healthy store/audit combination can
    # still use the grant afterward.
    result = good_engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success
