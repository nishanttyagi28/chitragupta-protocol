"""Unit tests for atomic authority budgets (Phase 12)."""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest

from karmasakshi.budget import AuthorityBudget, InMemoryBudgetLedger
from karmasakshi.errors import (
    AuthorityBudgetError,
    AuthorityBudgetExhaustedError,
    ConstraintWideningError,
)
from karmasakshi.grants.model import ScopeConstraints


def test_budget_model_shapes():
    monetary = AuthorityBudget(
        budget_id="b-money",
        kind="monetary",
        currency="INR",
        limit_minor_units=500_000,
    )
    assert monetary.limit() == 500_000
    assert monetary.canonical_hash().startswith("sha256:")

    count = AuthorityBudget(budget_id="b-count", kind="count", limit_count=3)
    assert count.limit() == 3

    with pytest.raises(ValueError):
        AuthorityBudget(budget_id="bad", kind="monetary", limit_minor_units=100)
    with pytest.raises(ValueError):
        AuthorityBudget(
            budget_id="bad2",
            kind="count",
            limit_count=1,
            currency="INR",
        )


def test_ledger_reserve_commit_release_and_exhaustion():
    ledger = InMemoryBudgetLedger()
    budget = AuthorityBudget(budget_id="b1", kind="count", limit_count=2)
    ledger.register(budget)
    assert ledger.remaining("b1") == 2
    assert ledger.reserve("b1", 1) is True
    assert ledger.remaining("b1") == 1
    ledger.commit("b1", 1)
    assert ledger.remaining("b1") == 1
    assert ledger.reserve("b1", 2) is False
    ledger.reserve("b1", 1)
    ledger.release("b1", 1)
    assert ledger.remaining("b1") == 1
    ledger.consume("b1", 1)
    assert ledger.remaining("b1") == 0
    with pytest.raises(AuthorityBudgetExhaustedError):
        ledger.consume("b1", 1)
    with pytest.raises(AuthorityBudgetError):
        ledger.get("missing")


def test_concurrent_reserves_do_not_oversubscribe():
    ledger = InMemoryBudgetLedger()
    ledger.register(AuthorityBudget(budget_id="c", kind="count", limit_count=1))
    wins = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        wins.append(ledger.reserve("c", 1))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for w in wins if w) == 1
    assert ledger.remaining("c") == 0


def _authorize(
    engine,
    sealed,
    issuer_signing_key,
    human_principal,
    agent_principal,
    now,
    *,
    authority_budget_id=None,
):
    return engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
        authority_budget_id=authority_budget_id,
    )


def test_monetary_budget_consumed_on_commit(
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
            budget_id="team-refunds",
            kind="monetary",
            currency="INR",
            limit_minor_units=200_000,
        )
    )
    engine = engine_factory(budget_ledger=ledger)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer_signing_key,
        human_principal,
        agent_principal,
        now,
        authority_budget_id="team-refunds",
    )
    assert grant.authority_budget_id == "team-refunds"
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success
    # default manifest estimated_cost is 150000 INR
    assert ledger.remaining("team-refunds") == 50_000


def test_budget_exhaustion_blocks_second_commit(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    ledger = InMemoryBudgetLedger()
    ledger.register(AuthorityBudget(budget_id="once", kind="count", limit_count=1))
    engine = engine_factory(budget_ledger=ledger)
    now = fixed_clock.now()

    first = engine.prepare(
        fake_adapter,
        manifest_factory(manifest_id="m-a", idempotency_key="idem-a", nonce="n-a"),
        context=None,
    )
    sealed1 = engine.seal(first, issuer_signing_key)
    g1 = _authorize(
        engine,
        sealed1,
        issuer_signing_key,
        human_principal,
        agent_principal,
        now,
        authority_budget_id="once",
    )
    assert engine.commit(sealed1, g1, fake_adapter, context=None).success

    second = engine.prepare(
        fake_adapter,
        manifest_factory(manifest_id="m-b", idempotency_key="idem-b", nonce="n-b"),
        context=None,
    )
    sealed2 = engine.seal(second, issuer_signing_key)
    g2 = _authorize(
        engine,
        sealed2,
        issuer_signing_key,
        human_principal,
        agent_principal,
        now,
        authority_budget_id="once",
    )
    with pytest.raises(AuthorityBudgetExhaustedError):
        engine.commit(sealed2, g2, fake_adapter, context=None)
    assert ledger.remaining("once") == 0


def test_unknown_budget_at_authorize_fails_closed(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    ledger = InMemoryBudgetLedger()
    engine = engine_factory(budget_ledger=ledger)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    with pytest.raises(AuthorityBudgetError, match="unknown"):
        _authorize(
            engine,
            sealed,
            issuer_signing_key,
            human_principal,
            agent_principal,
            now,
            authority_budget_id="missing",
        )


def test_budget_without_ledger_fails_closed(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    engine = engine_factory()  # no budget_ledger
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    with pytest.raises(AuthorityBudgetError, match="no budget_ledger"):
        _authorize(
            engine,
            sealed,
            issuer_signing_key,
            human_principal,
            agent_principal,
            now,
            authority_budget_id="any",
        )


def test_currency_mismatch_fails_closed(
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
            budget_id="usd-only",
            kind="monetary",
            currency="USD",
            limit_minor_units=1_000_000,
        )
    )
    engine = engine_factory(budget_ledger=ledger)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer_signing_key,
        human_principal,
        agent_principal,
        now,
        authority_budget_id="usd-only",
    )
    with pytest.raises(AuthorityBudgetError, match="currency"):
        engine.commit(sealed, grant, fake_adapter, context=None)


def test_failed_commit_releases_budget_reservation(
    engine_factory,
    manifest_factory,
    fake_adapter,
    fake_adapter_state,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    ledger = InMemoryBudgetLedger()
    ledger.register(AuthorityBudget(budget_id="rel", kind="count", limit_count=1))
    engine = engine_factory(budget_ledger=ledger)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        issuer_signing_key,
        human_principal,
        agent_principal,
        now,
        authority_budget_id="rel",
    )
    fake_adapter_state.fail_commit = True
    result = engine.commit(sealed, grant, fake_adapter, context=None)
    assert result.success is False
    assert ledger.remaining("rel") == 1


def test_monetary_budget_requires_positive_estimated_cost(manifest_factory):
    from karmasakshi.budget.consume import resolve_budget_consume_amount
    from karmasakshi.domain.common import MonetaryAmount

    budget = AuthorityBudget(
        budget_id="m",
        kind="monetary",
        currency="INR",
        limit_minor_units=100,
    )
    missing = manifest_factory(estimated_cost=None)
    with pytest.raises(AuthorityBudgetError, match="estimated_cost"):
        resolve_budget_consume_amount(budget, missing)
    zero = manifest_factory(estimated_cost=MonetaryAmount(currency="INR", minor_units=0))
    with pytest.raises(AuthorityBudgetError, match="minor_units"):
        resolve_budget_consume_amount(budget, zero)


def test_ledger_error_paths_and_assert_can_reserve():
    ledger = InMemoryBudgetLedger()
    ledger.register(AuthorityBudget(budget_id="e", kind="count", limit_count=1))
    with pytest.raises(AuthorityBudgetError):
        ledger.reserve("e", 0)
    with pytest.raises(AuthorityBudgetError):
        ledger.consume("e", 0)
    with pytest.raises(AuthorityBudgetError):
        ledger.release("e", 1)
    assert ledger.reserve("e", 1) is True
    with pytest.raises(AuthorityBudgetError):
        ledger.commit("e", 2)
    ledger.release("e", 1)
    with pytest.raises(AuthorityBudgetExhaustedError):
        ledger.assert_can_reserve("e", 2)
    ledger.assert_can_reserve("e", 1)
    ledger.commit("e", 1)


def test_grant_budget_binding_helpers(now, issuer_signing_key, human_principal):
    from karmasakshi.grants.issuer import issue_grant

    grant = issue_grant(
        grant_id="g-budget",
        issuer=human_principal,
        subject=human_principal,
        audience=("payment.simulator",),
        allowed_effect_types=("payment.transfer",),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        nonce="nb",
        signing_key=issuer_signing_key,
        manifest_hash="sha256:" + "a" * 64,
        authority_budget_id="budget-1",
    )
    assert grant.is_authority_budget_bound() is True
    assert grant.is_manifest_bound() is True
    assert grant.is_policy_bundle_bound() is False
    assert grant.is_quorum_bound() is False
    assert grant.is_decision_envelope_bound() is False
    assert grant.is_causal_graph_bound() is False
    with pytest.raises(ValueError):
        issue_grant(
            grant_id="g-bad",
            issuer=human_principal,
            subject=human_principal,
            audience=("payment.simulator",),
            allowed_effect_types=("payment.transfer",),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(hours=1),
            nonce="nb2",
            signing_key=issuer_signing_key,
            authority_budget_id="",
        )


def test_delegate_inherits_budget_and_rejects_swap(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    ledger = InMemoryBudgetLedger()
    ledger.register(AuthorityBudget(budget_id="parent-b", kind="count", limit_count=5))
    ledger.register(AuthorityBudget(budget_id="other-b", kind="count", limit_count=5))
    engine = engine_factory(budget_ledger=ledger)
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    root = _authorize(
        engine,
        sealed,
        issuer_signing_key,
        human_principal,
        agent_principal,
        now,
        authority_budget_id="parent-b",
    )
    child = engine.delegate(
        root,
        issuer=human_principal,
        subject=agent_principal,
        signing_key=issuer_signing_key,
        manifest_hash=sealed.seal.manifest_hash,
    )
    assert child.authority_budget_id == "parent-b"
    with pytest.raises(ConstraintWideningError, match="authority_budget_id"):
        engine.delegate(
            root,
            issuer=human_principal,
            subject=agent_principal,
            signing_key=issuer_signing_key,
            manifest_hash=sealed.seal.manifest_hash,
            authority_budget_id="other-b",
        )
