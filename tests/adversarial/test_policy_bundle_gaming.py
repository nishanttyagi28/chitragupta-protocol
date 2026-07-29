"""Adversarial tests for signed policy bundles: attempts to swap, forge,
replay, or otherwise defeat the binding between an ``ExecutionGrant`` and
the policy bundle it was authorized against.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import (
    InvalidSignatureError,
    PolicyBundleExpiredError,
    PolicyBundleIssuerNotAuthorizedError,
    PolicyBundleTamperedError,
    UnknownKeyError,
)
from karmasakshi.intelligence import IntelligencePolicy
from karmasakshi.intelligence.policy import build_policy_bundle
from karmasakshi.policy import seal_policy_bundle, verify_policy_bundle

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_HUMAN_ISSUER = Principal(principal_id="policy-admin", principal_type=PrincipalType.HUMAN)
_AGENT_ISSUER = Principal(principal_id="agent-1", principal_type=PrincipalType.AGENT)


def test_agent_cannot_be_policy_bundle_issuer():
    with pytest.raises(PolicyBundleIssuerNotAuthorizedError):
        build_policy_bundle(
            IntelligencePolicy(),
            bundle_id="b",
            bundle_version="1.0",
            issuer=_AGENT_ISSUER,
            created_at=_NOW,
            effective_from=_NOW,
        )


def test_service_principal_can_be_policy_bundle_issuer():
    service_issuer = Principal(principal_id="policy-service", principal_type=PrincipalType.SERVICE)
    bundle = build_policy_bundle(
        IntelligencePolicy(),
        bundle_id="b",
        bundle_version="1.0",
        issuer=service_issuer,
        created_at=_NOW,
        effective_from=_NOW,
    )
    assert bundle.issuer == service_issuer


def test_replayed_expired_bundle_cannot_be_reused_at_a_later_commit():
    signing_key = generate_signing_key("policy-signer")
    keyring = Keyring([signing_key.verification_key()])
    bundle = build_policy_bundle(
        IntelligencePolicy(),
        bundle_id="short-lived",
        bundle_version="1.0",
        issuer=_HUMAN_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
        effective_until=_NOW + timedelta(minutes=5),
    )
    sealed = seal_policy_bundle(bundle, signing_key, clock=FixedClock(_NOW))
    # Valid at authorize time...
    verify_policy_bundle(sealed, keyring, now=_NOW)
    # ...but an attacker replaying the same bundle well after its
    # effective window has closed must be rejected, not silently accepted
    # because it once verified successfully.
    with pytest.raises(PolicyBundleExpiredError):
        verify_policy_bundle(sealed, keyring, now=_NOW + timedelta(days=1))


def test_swapped_key_id_with_stolen_signature_fails_closed():
    """Even if an attacker captures a valid (bundle_hash, signature) pair
    from one bundle, presenting it against a different bundle whose
    payload differs must fail integrity verification before the signature
    is even checked."""
    signing_key = generate_signing_key("policy-signer")
    keyring = Keyring([signing_key.verification_key()])
    legit = build_policy_bundle(
        IntelligencePolicy(block_threshold=85),
        bundle_id="legit",
        bundle_version="1.0",
        issuer=_HUMAN_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    sealed_legit = seal_policy_bundle(legit, signing_key, clock=FixedClock(_NOW))

    attacker_bundle = build_policy_bundle(
        IntelligencePolicy(block_threshold=1, review_threshold=0),
        bundle_id="legit",
        bundle_version="1.0",
        issuer=_HUMAN_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    # Attacker grafts the legitimate seal onto their own (more permissive)
    # bundle content.
    forged = sealed_legit.model_copy(update={"bundle": attacker_bundle})
    with pytest.raises(PolicyBundleTamperedError):
        verify_policy_bundle(forged, keyring, now=_NOW)


def test_unknown_signer_key_is_never_trusted_regardless_of_content():
    attacker_key = generate_signing_key("attacker")
    empty_keyring = Keyring([])
    bundle = build_policy_bundle(
        IntelligencePolicy(),
        bundle_id="b",
        bundle_version="1.0",
        issuer=_HUMAN_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    sealed = seal_policy_bundle(bundle, attacker_key, clock=FixedClock(_NOW))
    with pytest.raises(UnknownKeyError):
        verify_policy_bundle(sealed, empty_keyring, now=_NOW)


def test_signature_from_a_different_bundle_entirely_is_rejected():
    key_a = generate_signing_key("signer-a")
    key_b = generate_signing_key("signer-b")
    keyring = Keyring([key_a.verification_key(), key_b.verification_key()])

    bundle_a = build_policy_bundle(
        IntelligencePolicy(block_threshold=85),
        bundle_id="a",
        bundle_version="1.0",
        issuer=_HUMAN_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    bundle_b = build_policy_bundle(
        IntelligencePolicy(block_threshold=10, review_threshold=0),
        bundle_id="b",
        bundle_version="1.0",
        issuer=_HUMAN_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    sealed_a = seal_policy_bundle(bundle_a, key_a, clock=FixedClock(_NOW))
    # Take bundle B's content but attach A's seal (whose signature covers
    # A's hash, not B's) -- integrity check must catch the hash mismatch
    # before signature verification is even attempted.
    frankenstein = sealed_a.model_copy(update={"bundle": bundle_b})
    with pytest.raises(PolicyBundleTamperedError):
        verify_policy_bundle(frankenstein, keyring, now=_NOW)


def test_forged_signature_bytes_over_correct_hash_still_rejected():
    signing_key = generate_signing_key("policy-signer")
    attacker_key = generate_signing_key("attacker")
    keyring = Keyring([signing_key.verification_key()])
    bundle = build_policy_bundle(
        IntelligencePolicy(),
        bundle_id="b",
        bundle_version="1.0",
        issuer=_HUMAN_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    sealed = seal_policy_bundle(bundle, signing_key, clock=FixedClock(_NOW))
    forged_seal = sealed.seal.model_copy(
        update={"signature": attacker_key.sign(sealed.seal.bundle_hash.encode("utf-8"))}
    )
    forged = sealed.model_copy(update={"seal": forged_seal})
    with pytest.raises(InvalidSignatureError):
        verify_policy_bundle(forged, keyring, now=_NOW)
