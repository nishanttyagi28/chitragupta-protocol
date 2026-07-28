from __future__ import annotations

import pytest

from chitragupta.adapters.email_sandbox import EmailRequest, EmailSandboxAdapter, SandboxOutbox
from chitragupta.errors import RecipientNotAllowedError


@pytest.fixture
def outbox():
    return SandboxOutbox()


def test_send_and_verify(outbox, agent_principal, human_principal):
    adapter = EmailSandboxAdapter(outbox)
    req = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("alice@example.com",),
        subject="Invoice",
        body="Please pay invoice 42",
        idempotency_key="idem-email-1",
    )
    manifest = adapter.prepare(req, context=None)
    result = adapter.commit(manifest, grant=None, context=None)
    assert result.success
    proof = adapter.verify(manifest, result, context=None)
    assert proof.matched_expected
    assert len(outbox.all_messages()) == 1


def test_recipient_allow_list_blocks_disallowed(agent_principal, human_principal):
    outbox = SandboxOutbox()
    adapter = EmailSandboxAdapter(outbox, allowed_recipients=frozenset({"alice@example.com"}))
    req = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("mallory@example.com",),
        subject="x",
        body="y",
        idempotency_key="idem-email-2",
    )
    with pytest.raises(RecipientNotAllowedError):
        adapter.prepare(req, context=None)


def test_recipient_allow_list_permits_allowed(agent_principal, human_principal):
    outbox = SandboxOutbox()
    adapter = EmailSandboxAdapter(outbox, allowed_recipients=frozenset({"alice@example.com"}))
    req = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("alice@example.com",),
        subject="x",
        body="y",
        idempotency_key="idem-email-3",
    )
    manifest = adapter.prepare(req, context=None)
    result = adapter.commit(manifest, grant=None, context=None)
    assert result.success


def test_idempotent_delivery_does_not_duplicate(outbox, agent_principal, human_principal):
    adapter = EmailSandboxAdapter(outbox)
    req = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("bob@example.com",),
        subject="Hi",
        body="Body text",
        idempotency_key="idem-email-4",
    )
    manifest = adapter.prepare(req, context=None)
    result1 = adapter.commit(manifest, grant=None, context=None)
    result2 = adapter.commit(manifest, grant=None, context=None)
    assert result1.provider_reference == result2.provider_reference
    assert len(outbox.all_messages()) == 1


def test_irreversible_after_send_refuses_compensation(outbox, agent_principal, human_principal):
    adapter = EmailSandboxAdapter(outbox)
    req = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("carol@example.com",),
        subject="x",
        body="y",
        idempotency_key="idem-email-5",
    )
    manifest = adapter.prepare(req, context=None)
    assert manifest.reversibility.value == "irreversible"
    result = adapter.commit(manifest, grant=None, context=None)
    compensation = adapter.compensate(manifest, result, context=None)
    assert compensation.attempted is False
    assert compensation.succeeded is False
    assert "irreversible" in (compensation.reason or "")


def test_attachments_digested_not_stored_raw(outbox, agent_principal, human_principal):
    adapter = EmailSandboxAdapter(outbox)
    req = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("dave@example.com",),
        subject="x",
        body="y",
        attachments=(b"file-content-one", b"file-content-two"),
        idempotency_key="idem-email-6",
    )
    manifest = adapter.prepare(req, context=None)
    assert manifest.parameters["attachment_count"] == 2
    assert "attachment_digests" in manifest.parameters
    assert b"file-content-one" not in str(manifest.parameters).encode("utf-8")


def test_verify_detects_mismatch_via_independent_outbox_read(
    outbox, agent_principal, human_principal
):
    adapter = EmailSandboxAdapter(outbox)
    req = EmailRequest(
        actor=agent_principal,
        principal=human_principal,
        recipients=("erin@example.com",),
        subject="Subject A",
        body="Body A",
        idempotency_key="idem-email-7",
    )
    manifest = adapter.prepare(req, context=None)
    result = adapter.commit(manifest, grant=None, context=None)

    # Simulate a manifest that claims a different subject than what was actually sent.
    forged_manifest = manifest.model_copy(
        update={"parameters": {**manifest.parameters, "subject": "Subject B"}}
    )
    proof = adapter.verify(forged_manifest, result, context=None)
    assert not proof.matched_expected
