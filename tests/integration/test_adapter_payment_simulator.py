from __future__ import annotations

import pytest

from chitragupta.adapters.payment_simulator import (
    PaymentRequest,
    PaymentSimulator,
    PaymentSimulatorAdapter,
)


@pytest.fixture
def simulator():
    sim = PaymentSimulator()
    sim.fund_account("acct-src", 1_000_000)
    return sim


@pytest.fixture
def adapter(simulator):
    return PaymentSimulatorAdapter(simulator)


def _request(actor, principal, **kwargs):
    kwargs.setdefault("actor", actor)
    kwargs.setdefault("principal", principal)
    kwargs.setdefault("source_account", "acct-src")
    kwargs.setdefault("currency", "INR")
    return PaymentRequest(**kwargs)


def test_successful_payment_and_verify(adapter, simulator, agent_principal, human_principal):
    req = _request(
        agent_principal,
        human_principal,
        beneficiary="merchant-A",
        amount_minor_units=150000,
        reference="invoice-1",
        idempotency_key="idem-pay-1",
    )
    manifest = adapter.prepare(req, context=None)
    precondition = adapter.validate_preconditions(manifest, context=None)
    assert precondition.satisfied
    result = adapter.commit(manifest, grant=None, context=None)
    assert result.success
    proof = adapter.verify(manifest, result, context=None)
    assert proof.matched_expected
    assert simulator.get_balance("acct-src") == 1_000_000 - 150000


def test_duplicate_retry_prevention_via_provider_idempotency(
    adapter, simulator, agent_principal, human_principal
):
    req = _request(
        agent_principal,
        human_principal,
        beneficiary="merchant-A",
        amount_minor_units=100000,
        reference="invoice-2",
        idempotency_key="idem-pay-2",
    )
    manifest = adapter.prepare(req, context=None)
    result1 = adapter.commit(manifest, grant=None, context=None)
    result2 = adapter.commit(manifest, grant=None, context=None)
    assert result1.success and result2.success
    # balance only deducted once despite two commit() calls with the same idempotency key
    assert simulator.get_balance("acct-src") == 1_000_000 - 100000


def test_injected_failure_reported_and_no_funds_moved(
    adapter, simulator, agent_principal, human_principal
):
    simulator.inject_failure()
    req = _request(
        agent_principal,
        human_principal,
        beneficiary="merchant-A",
        amount_minor_units=50000,
        reference="invoice-3",
        idempotency_key="idem-pay-3",
    )
    manifest = adapter.prepare(req, context=None)
    result = adapter.commit(manifest, grant=None, context=None)
    assert not result.success
    assert simulator.get_balance("acct-src") == 1_000_000


def test_stale_balance_detected_before_commit(adapter, simulator, agent_principal, human_principal):
    req = _request(
        agent_principal,
        human_principal,
        beneficiary="merchant-A",
        amount_minor_units=100000,
        reference="invoice-4",
        idempotency_key="idem-pay-4a",
    )
    manifest = adapter.prepare(req, context=None)

    # Balance drains between prepare() and commit() (e.g. a different payment clears first).
    other_req = _request(
        agent_principal,
        human_principal,
        beneficiary="merchant-B",
        amount_minor_units=900000,
        reference="invoice-4b",
        idempotency_key="idem-pay-4b",
    )
    other_manifest = adapter.prepare(other_req, context=None)
    other_result = adapter.commit(other_manifest, grant=None, context=None)
    assert other_result.success

    precondition = adapter.validate_preconditions(manifest, context=None)
    assert not precondition.satisfied


def test_ambiguous_timeout_settles_but_reports_failure(
    adapter, simulator, agent_principal, human_principal
):
    simulator.inject_ambiguous_timeout()
    req = _request(
        agent_principal,
        human_principal,
        beneficiary="merchant-A",
        amount_minor_units=200000,
        reference="invoice-5",
        idempotency_key="idem-pay-5",
    )
    manifest = adapter.prepare(req, context=None)
    result = adapter.commit(manifest, grant=None, context=None)
    # The adapter reports failure/ambiguity to the caller...
    assert not result.success
    assert "ambiguous" in (result.detail or "")
    # ...but the provider actually settled the payment internally.
    record = simulator.get_payment("idem-pay-5")
    assert record is not None
    assert record.status == "settled"
    assert simulator.get_balance("acct-src") == 1_000_000 - 200000

    # Independent verification (not trusting commit_result) discovers the truth.
    proof = adapter.verify(manifest, result, context=None)
    assert proof.matched_expected


def test_compensation_of_settled_payment_is_honestly_refused(
    adapter, simulator, agent_principal, human_principal
):
    req = _request(
        agent_principal,
        human_principal,
        beneficiary="merchant-A",
        amount_minor_units=75000,
        reference="invoice-6",
        idempotency_key="idem-pay-6",
    )
    manifest = adapter.prepare(req, context=None)
    result = adapter.commit(manifest, grant=None, context=None)
    assert result.success
    compensation = adapter.compensate(manifest, result, context=None)
    assert compensation.attempted is True
    assert compensation.succeeded is False
    assert "cannot be reversed" in (compensation.reason or "")


def test_compensation_of_failed_payment_is_noop(
    adapter, simulator, agent_principal, human_principal
):
    simulator.inject_failure()
    req = _request(
        agent_principal,
        human_principal,
        beneficiary="merchant-A",
        amount_minor_units=10000,
        reference="invoice-7",
        idempotency_key="idem-pay-7",
    )
    manifest = adapter.prepare(req, context=None)
    result = adapter.commit(manifest, grant=None, context=None)
    compensation = adapter.compensate(manifest, result, context=None)
    assert compensation.attempted is False
