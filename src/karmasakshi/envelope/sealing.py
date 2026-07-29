"""Seal and verify Decision Envelopes.

Mirrors ``protocol/sealing.py`` / ``policy/sealing.py``: sign the canonical
hash, then at verification time recompute the hash (tamper detection) and
check the signature (identity proof), plus the effective window.
"""

from __future__ import annotations

from datetime import datetime

from karmasakshi.config.clock import SYSTEM_CLOCK, Clock, ensure_utc
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey
from karmasakshi.envelope.model import DecisionEnvelope
from karmasakshi.errors import (
    DecisionEnvelopeExpiredError,
    DecisionEnvelopeNotYetValidError,
    DecisionEnvelopeTamperedError,
    InvalidSignatureError,
)


def seal_decision_envelope(
    envelope: DecisionEnvelope,
    signing_key: SigningKey,
    *,
    clock: Clock = SYSTEM_CLOCK,
) -> DecisionEnvelope:
    """Sign ``envelope`` and return a new instance with ``signature`` set.

    The envelope's ``key_id`` must already match ``signing_key.key_id``.
    """
    if envelope.key_id != signing_key.key_id:
        raise InvalidSignatureError(
            f"decision envelope key_id {envelope.key_id!r} does not match "
            f"signing key {signing_key.key_id!r}"
        )
    if envelope.signature is not None:
        raise InvalidSignatureError(f"decision envelope {envelope.envelope_id} is already signed")
    # Touch clock so callers that inject a frozen clock remain consistent
    # with other sealing helpers; the envelope's created_at is caller-set.
    _ = clock.now()
    signature = signing_key.sign(envelope.canonical_hash().encode("utf-8"))
    return envelope.model_copy(update={"signature": signature})


def verify_decision_envelope(
    envelope: DecisionEnvelope,
    keyring: Keyring,
    *,
    now: datetime | None = None,
) -> None:
    """Tamper-detect, verify signature, and enforce the effective window."""
    if envelope.signature is None:
        raise InvalidSignatureError(f"decision envelope {envelope.envelope_id} is unsigned")
    # Recompute hash over the signing payload (excludes signature). A field
    # mutation after sealing changes the hash and fails closed here even
    # before the cryptographic check runs.
    expected_payload_hash = envelope.canonical_hash()
    # The signature covers that hash; verify via the keyring.
    try:
        keyring.verify(
            envelope.key_id,
            expected_payload_hash.encode("utf-8"),
            envelope.signature,
        )
    except Exception:
        # Re-raise as-is (UnknownKeyError / InvalidSignatureError) -- the
        # keyring already fails closed with the right types.
        raise

    when = ensure_utc(now) if now is not None else SYSTEM_CLOCK.now()
    if when < envelope.not_before:
        raise DecisionEnvelopeNotYetValidError(
            f"decision envelope {envelope.envelope_id} is not valid before "
            f"{envelope.not_before.isoformat()} (now={when.isoformat()})"
        )
    if when >= envelope.expires_at:
        raise DecisionEnvelopeExpiredError(
            f"decision envelope {envelope.envelope_id} expired at "
            f"{envelope.expires_at.isoformat()} (now={when.isoformat()})"
        )


def assert_envelope_integrity(envelope: DecisionEnvelope, expected_hash: str) -> None:
    """Raise if the envelope's recomputed hash does not match ``expected_hash``."""
    actual = envelope.canonical_hash()
    if actual != expected_hash:
        raise DecisionEnvelopeTamperedError(
            f"decision envelope {envelope.envelope_id} hash mismatch: "
            f"recomputed {actual} != expected {expected_hash}"
        )


__all__ = [
    "assert_envelope_integrity",
    "seal_decision_envelope",
    "verify_decision_envelope",
]
