"""Adversarial tests for authority budget gaming (Phase 12)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.budget import AuthorityBudget, InMemoryBudgetLedger
from karmasakshi.errors import AuthorityBudgetError, AuthorityBudgetExhaustedError
from karmasakshi.grants.model import ScopeConstraints


def test_cannot_bind_budget_then_remove_ledger_at_commit(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    """A grant signed with a budget id must fail closed if the ledger disappears."""
    ledger = InMemoryBudgetLedger()
    ledger.register(AuthorityBudget(budget_id="ephemeral", kind="count", limit_count=2))
    engine = engine_factory(budget_ledger=ledger)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
        authority_budget_id="ephemeral",
    )
    engine.context.budget_ledger = None
    with pytest.raises(AuthorityBudgetError, match="no budget_ledger"):
        engine.commit(sealed, grant, fake_adapter, context=None)


def test_reregister_conflicting_budget_definition_rejected():
    ledger = InMemoryBudgetLedger()
    a = AuthorityBudget(budget_id="x", kind="count", limit_count=1)
    b = AuthorityBudget(budget_id="x", kind="count", limit_count=99)
    ledger.register(a)
    with pytest.raises(AuthorityBudgetError, match="different definition"):
        ledger.register(b)


def test_shared_budget_across_two_grants_is_atomic(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    ledger = InMemoryBudgetLedger()
    ledger.register(
        AuthorityBudget(
            budget_id="shared",
            kind="monetary",
            currency="INR",
            limit_minor_units=150_000,
        )
    )
    engine = engine_factory(budget_ledger=ledger)
    now = fixed_clock.now()

    m1 = engine.prepare(
        fake_adapter,
        manifest_factory(manifest_id="m-s1", idempotency_key="s1", nonce="ns1"),
        context=None,
    )
    s1 = engine.seal(m1, issuer_signing_key)
    g1 = engine.authorize(
        s1,
        issuer=human_principal,
        subject=agent_principal,
        audience=(s1.manifest.adapter.adapter_id,),
        allowed_effect_types=(s1.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
        authority_budget_id="shared",
    )
    assert engine.commit(s1, g1, fake_adapter, context=None).success

    m2 = engine.prepare(
        fake_adapter,
        manifest_factory(manifest_id="m-s2", idempotency_key="s2", nonce="ns2"),
        context=None,
    )
    s2 = engine.seal(m2, issuer_signing_key)
    g2 = engine.authorize(
        s2,
        issuer=human_principal,
        subject=agent_principal,
        audience=(s2.manifest.adapter.adapter_id,),
        allowed_effect_types=(s2.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
        authority_budget_id="shared",
    )
    with pytest.raises(AuthorityBudgetExhaustedError):
        engine.commit(s2, g2, fake_adapter, context=None)
