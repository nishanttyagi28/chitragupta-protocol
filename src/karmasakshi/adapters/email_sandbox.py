"""Email sandbox adapter.

Never sends real email. Delivery lands in an in-memory :class:`SandboxOutbox`
that tests/demos can inspect directly, which is what makes "verification by
independently observed state" meaningful here: :meth:`EmailSandboxAdapter.verify`
re-reads the outbox rather than trusting the commit result.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from karmasakshi.adapters.base import (
    CommitResult,
    CompensationResult,
    OutcomeProof,
    PreconditionResult,
)
from karmasakshi.canonical.serialize import digest_bytes
from karmasakshi.domain.common import AdapterIdentity, Principal
from karmasakshi.domain.enums import (
    BlastRadiusClassification,
    ReversibilityClassification,
    RiskClassification,
)
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.errors import RecipientNotAllowedError


@dataclass(frozen=True)
class EmailRequest:
    actor: Principal
    principal: Principal
    recipients: tuple[str, ...]
    subject: str
    body: str
    attachments: tuple[bytes, ...] = ()
    idempotency_key: str = ""
    ttl_seconds: int = 300


@dataclass(frozen=True)
class SentMessage:
    message_id: str
    recipients: tuple[str, ...]
    subject: str
    body_digest: str
    attachment_digests: tuple[str, ...]
    sent_at: datetime


class SandboxOutbox:
    """The adapter's independent external system of record."""

    def __init__(self) -> None:
        self._by_idempotency_key: dict[str, SentMessage] = {}

    def deliver(self, idempotency_key: str, message: SentMessage) -> SentMessage:
        existing = self._by_idempotency_key.get(idempotency_key)
        if existing is not None:
            return existing
        self._by_idempotency_key[idempotency_key] = message
        return message

    def get(self, idempotency_key: str) -> SentMessage | None:
        return self._by_idempotency_key.get(idempotency_key)

    def all_messages(self) -> list[SentMessage]:
        return list(self._by_idempotency_key.values())


class EmailSandboxAdapter:
    adapter_id = "email.sandbox"
    adapter_version = "1.0.0"

    def __init__(
        self, outbox: SandboxOutbox, allowed_recipients: frozenset[str] | None = None
    ) -> None:
        self.outbox = outbox
        self.allowed_recipients = allowed_recipients
        self._identity = AdapterIdentity(
            adapter_id=self.adapter_id, adapter_version=self.adapter_version
        )

    def prepare(self, request: EmailRequest, context: Any) -> EffectManifest:
        if self.allowed_recipients is not None:
            disallowed = set(request.recipients) - self.allowed_recipients
            if disallowed:
                raise RecipientNotAllowedError(
                    f"recipients not on allow-list: {sorted(disallowed)}"
                )

        now = datetime.now(timezone.utc)
        body_digest = digest_bytes(request.body.encode("utf-8"))
        attachment_digests = tuple(digest_bytes(a) for a in request.attachments)
        recipients_key = ",".join(sorted(request.recipients))

        parameters: dict[str, Any] = {
            "recipients": recipients_key,
            "recipient_count": len(request.recipients),
            "subject": request.subject,
            "body_digest": body_digest,
            "attachment_count": len(request.attachments),
        }
        if attachment_digests:
            parameters["attachment_digests"] = ",".join(attachment_digests)

        return EffectManifest(
            manifest_id=str(uuid.uuid4()),
            effect_type="email.send",
            actor=request.actor,
            principal=request.principal,
            adapter=self._identity,
            target_resource=f"email:{recipients_key}",
            parameters=parameters,
            risk=RiskClassification.MEDIUM,
            reversibility=ReversibilityClassification.IRREVERSIBLE,
            blast_radius=(
                BlastRadiusClassification.SINGLE_RESOURCE
                if len(request.recipients) <= 1
                else BlastRadiusClassification.BOUNDED_SET
            ),
            idempotency_key=request.idempotency_key or f"email-{body_digest}",
            created_at=now,
            expires_at=now + timedelta(seconds=request.ttl_seconds),
            nonce=uuid.uuid4().hex,
            metadata={"attachments": str(len(request.attachments))},
        )

    def validate_preconditions(self, manifest: EffectManifest, context: Any) -> PreconditionResult:
        return PreconditionResult(satisfied=True)

    def commit(self, manifest: EffectManifest, grant: Any, context: Any) -> CommitResult:
        existing = self.outbox.get(manifest.idempotency_key)
        if existing is not None:
            return CommitResult(
                success=True,
                idempotency_key=manifest.idempotency_key,
                provider_reference=existing.message_id,
                detail="idempotent delivery: message already in outbox",
                after_state_digest=existing.body_digest,
            )
        recipients = tuple(str(manifest.parameters["recipients"]).split(","))
        message = SentMessage(
            message_id=str(uuid.uuid4()),
            recipients=recipients,
            subject=str(manifest.parameters["subject"]),
            body_digest=str(manifest.parameters["body_digest"]),
            attachment_digests=tuple(
                str(manifest.parameters.get("attachment_digests", "")).split(",")
            )
            if manifest.parameters.get("attachment_digests")
            else (),
            sent_at=datetime.now(timezone.utc),
        )
        delivered = self.outbox.deliver(manifest.idempotency_key, message)
        return CommitResult(
            success=True,
            idempotency_key=manifest.idempotency_key,
            provider_reference=delivered.message_id,
            after_state_digest=delivered.body_digest,
        )

    def verify(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> OutcomeProof:
        message = self.outbox.get(manifest.idempotency_key)
        if message is None:
            return OutcomeProof(
                matched_expected=False,
                observed_at=datetime.now(timezone.utc),
                detail="no message found in sandbox outbox",
            )
        expected_recipients = tuple(str(manifest.parameters["recipients"]).split(","))
        matched = (
            message.recipients == expected_recipients
            and message.subject == str(manifest.parameters["subject"])
            and message.body_digest == str(manifest.parameters["body_digest"])
        )
        return OutcomeProof(
            matched_expected=matched,
            observed_at=datetime.now(timezone.utc),
            observed_after_state_digest=message.body_digest,
        )

    def compensate(
        self, manifest: EffectManifest, commit_result: CommitResult, context: Any
    ) -> CompensationResult:
        return CompensationResult(
            attempted=False,
            succeeded=False,
            reason="email is irreversible once sent; the sandbox does not support recall",
        )


__all__ = ["EmailRequest", "EmailSandboxAdapter", "SandboxOutbox", "SentMessage"]
