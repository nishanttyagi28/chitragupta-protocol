"""End-to-end tests running real adapters (not the test FakeAdapter) through
the actual KarmaSakshiEngine: prepare -> seal -> authorize -> commit -> verify.
"""

from __future__ import annotations

from datetime import timedelta

from karmasakshi.adapters.email_sandbox import EmailRequest, EmailSandboxAdapter, SandboxOutbox
from karmasakshi.adapters.payment_simulator import (
    PaymentRequest,
    PaymentSimulator,
    PaymentSimulatorAdapter,
)
from karmasakshi.grants.model import ScopeConstraints


def _authorize(engine, sealed, adapter, *, issuer, subject, issuer_signing_key, now):
    return engine.authorize(
        sealed,
        issuer=issuer,
        subject=subject,
        audience=(adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        signing_key=issuer_signing_key,
    )


def test_payment_simulator_end_to_end_through_engine(
    engine_factory, agent_principal, human_principal, service_principal, issuer_signing_key, now
):
    engine = engine_factory()
    simulator = PaymentSimulator()
    simulator.fund_account("acct-src", 500_000)
    adapter = PaymentSimulatorAdapter(simulator)

    request = PaymentRequest(
        actor=agent_principal,
        principal=human_principal,
        source_account="acct-src",
        beneficiary="merchant-A",
        amount_minor_units=150_000,
        currency="INR",
        reference="invoice-e2e-1",
        idempotency_key="idem-e2e-1",
    )
    manifest = engine.prepare(adapter, request, context=None)
    sealed = engine.seal(manifest, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        adapter,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )
    result = engine.commit(sealed, grant, adapter, context=None)
    assert result.success
    proof = engine.verify(sealed.manifest, result, adapter, context=None)
    assert proof.matched_expected
    assert simulator.get_balance("acct-src") == 350_000


def test_email_sandbox_end_to_end_through_engine(
    engine_factory, agent_principal, human_principal, service_principal, issuer_signing_key, now
):
    engine = engine_factory()
    outbox = SandboxOutbox()
    adapter = EmailSandboxAdapter(outbox)

    request = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("alice@example.com",),
        subject="Your invoice",
        body="Please find attached invoice details.",
        idempotency_key="idem-e2e-email-1",
    )
    manifest = engine.prepare(adapter, request, context=None)
    sealed = engine.seal(manifest, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        adapter,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )
    result = engine.commit(sealed, grant, adapter, context=None)
    assert result.success
    proof = engine.verify(sealed.manifest, result, adapter, context=None)
    assert proof.matched_expected
    assert len(outbox.all_messages()) == 1


def test_email_sandbox_changed_recipient_after_seal_is_blocked(
    engine_factory, agent_principal, human_principal, service_principal, issuer_signing_key, now
):
    import pytest

    from karmasakshi.errors import ManifestTamperedError

    engine = engine_factory()
    outbox = SandboxOutbox()
    adapter = EmailSandboxAdapter(outbox)

    request = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("alice@example.com",),
        subject="Subj",
        body="Body",
        idempotency_key="idem-e2e-email-2",
    )
    manifest = engine.prepare(adapter, request, context=None)
    sealed = engine.seal(manifest, issuer_signing_key)
    grant = _authorize(
        engine,
        sealed,
        adapter,
        issuer=service_principal,
        subject=agent_principal,
        issuer_signing_key=issuer_signing_key,
        now=now,
    )

    tampered_request = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("attacker@example.com",),
        subject="Subj",
        body="Body",
        idempotency_key="idem-e2e-email-2",
    )
    tampered_manifest = adapter.prepare(tampered_request, context=None)
    tampered_sealed = sealed.model_copy(update={"manifest": tampered_manifest})

    with pytest.raises(ManifestTamperedError):
        engine.commit(tampered_sealed, grant, adapter, context=None)
    assert len(outbox.all_messages()) == 0
