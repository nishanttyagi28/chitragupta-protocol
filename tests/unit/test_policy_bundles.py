from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from karmasakshi.crypto import Keyring, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import (
    InvalidSignatureError,
    PolicyBundleExpiredError,
    PolicyBundleNotYetEffectiveError,
    PolicyBundleTamperedError,
    PolicyBundleTypeMismatchError,
    UnknownKeyError,
)
from karmasakshi.intelligence import IntelligencePolicy
from karmasakshi.intelligence.policy import (
    POLICY_TYPE_INTELLIGENCE,
    build_policy_bundle,
    policy_from_bundle_payload,
)
from karmasakshi.policy import PolicyBundle, seal_policy_bundle, verify_policy_bundle

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_ISSUER = Principal(principal_id="policy-admin", principal_type=PrincipalType.HUMAN)


@pytest.fixture
def signing_key():
    return generate_signing_key("policy-signer-1")


@pytest.fixture
def keyring(signing_key):
    return Keyring([signing_key.verification_key()])


def _bundle(**overrides) -> PolicyBundle:
    kwargs = {
        "bundle_id": "bundle-1",
        "bundle_version": "1.0",
        "issuer": _ISSUER,
        "created_at": _NOW,
        "effective_from": _NOW,
        "effective_until": _NOW + timedelta(days=30),
    }
    kwargs.update(overrides)
    return build_policy_bundle(IntelligencePolicy(), **kwargs)


# --- PolicyBundle construction -------------------------------------------------


def test_bundle_hash_deterministic_across_construction_order():
    policy = IntelligencePolicy(restricted_effect_types=("a", "b"))
    b1 = build_policy_bundle(
        policy,
        bundle_id="x",
        bundle_version="1.0",
        issuer=_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    b2 = build_policy_bundle(
        IntelligencePolicy(restricted_effect_types=("b", "a")),
        bundle_id="x",
        bundle_version="1.0",
        issuer=_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    assert b1.canonical_hash() == b2.canonical_hash()


def test_bundle_hash_changes_when_payload_differs():
    b1 = _bundle()
    b2 = build_policy_bundle(
        IntelligencePolicy(block_threshold=99),
        bundle_id="bundle-1",
        bundle_version="1.0",
        issuer=_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    assert b1.canonical_hash() != b2.canonical_hash()


def test_bundle_rejects_effective_until_before_from():
    with pytest.raises(ValueError):
        _bundle(effective_from=_NOW, effective_until=_NOW - timedelta(days=1))


def test_bundle_rejects_oversized_payload():
    huge_policy = IntelligencePolicy(
        sensitive_target_patterns=tuple(f"pattern-{i}" * 50 for i in range(200))
    )
    with pytest.raises(ValueError):
        build_policy_bundle(
            huge_policy,
            bundle_id="huge",
            bundle_version="1.0",
            issuer=_ISSUER,
            created_at=_NOW,
            effective_from=_NOW,
        )


def test_is_effective_at():
    bundle = _bundle(effective_from=_NOW, effective_until=_NOW + timedelta(days=1))
    assert bundle.is_effective_at(_NOW) is True
    assert bundle.is_effective_at(_NOW + timedelta(hours=12)) is True
    assert bundle.is_effective_at(_NOW - timedelta(seconds=1)) is False
    assert bundle.is_effective_at(_NOW + timedelta(days=1)) is False  # exclusive upper bound
    assert bundle.is_effective_at(_NOW + timedelta(days=2)) is False


def test_no_effective_until_means_open_ended():
    bundle = _bundle(effective_until=None)
    assert bundle.is_effective_at(_NOW + timedelta(days=3650)) is True


# --- sealing / verification -----------------------------------------------------


def test_seal_and_verify_round_trip(signing_key, keyring):
    sealed = seal_policy_bundle(_bundle(), signing_key)
    verify_policy_bundle(sealed, keyring, now=_NOW)  # must not raise


def test_verify_rejects_type_mismatch(signing_key, keyring):
    sealed = seal_policy_bundle(_bundle(), signing_key)
    with pytest.raises(PolicyBundleTypeMismatchError):
        verify_policy_bundle(sealed, keyring, now=_NOW, expected_policy_type="something.else")
    verify_policy_bundle(sealed, keyring, now=_NOW, expected_policy_type=POLICY_TYPE_INTELLIGENCE)


def test_verify_rejects_not_yet_effective(signing_key, keyring):
    bundle = _bundle(effective_from=_NOW + timedelta(days=1))
    sealed = seal_policy_bundle(bundle, signing_key)
    with pytest.raises(PolicyBundleNotYetEffectiveError):
        verify_policy_bundle(sealed, keyring, now=_NOW)


def test_verify_rejects_expired(signing_key, keyring):
    bundle = _bundle(effective_from=_NOW, effective_until=_NOW + timedelta(days=1))
    sealed = seal_policy_bundle(bundle, signing_key)
    with pytest.raises(PolicyBundleExpiredError):
        verify_policy_bundle(sealed, keyring, now=_NOW + timedelta(days=2))


def test_verify_rejects_tampered_payload(signing_key, keyring):
    sealed = seal_policy_bundle(_bundle(), signing_key)
    tampered_bundle = sealed.bundle.model_copy(
        update={"payload": {**sealed.bundle.payload, "block_threshold": 1}}
    )
    tampered = sealed.model_copy(update={"bundle": tampered_bundle})
    with pytest.raises(PolicyBundleTamperedError):
        verify_policy_bundle(tampered, keyring, now=_NOW)


def test_verify_rejects_unknown_key(signing_key):
    sealed = seal_policy_bundle(_bundle(), signing_key)
    empty_keyring = Keyring([])
    with pytest.raises(UnknownKeyError):
        verify_policy_bundle(sealed, empty_keyring, now=_NOW)


def test_verify_rejects_forged_signature_with_unchanged_content(signing_key, keyring):
    other_key = generate_signing_key("attacker-key")
    sealed = seal_policy_bundle(_bundle(), signing_key)
    forged_seal = sealed.seal.model_copy(
        update={"signature": other_key.sign(sealed.seal.bundle_hash.encode("utf-8"))}
    )
    forged = sealed.model_copy(update={"seal": forged_seal})
    with pytest.raises(InvalidSignatureError):
        verify_policy_bundle(forged, keyring, now=_NOW)


# --- payload round-trip ----------------------------------------------------------


def test_policy_round_trips_through_bundle_payload():
    original = IntelligencePolicy(
        policy_id="strict",
        block_threshold=70,
        review_threshold=30,
        restricted_effect_types=("payment.wire", "db.drop"),
        sensitive_target_patterns=(r"admin", r"root"),
        amount_thresholds={"INR": (1000, 5000, 10000), "USD": (10, 50, 100)},
        max_acceptable_failure_rate=0.15,
    )
    bundle = build_policy_bundle(
        original,
        bundle_id="rt",
        bundle_version="1.0",
        issuer=_ISSUER,
        created_at=_NOW,
        effective_from=_NOW,
    )
    reconstructed = policy_from_bundle_payload(bundle.payload)
    assert reconstructed.policy_hash() == original.policy_hash()


def test_policy_from_bundle_payload_rejects_missing_key():
    with pytest.raises(ValueError):
        policy_from_bundle_payload({"policy_id": "x"})


def test_policy_from_bundle_payload_rejects_wrong_type():
    payload = IntelligencePolicy().canonical_dict()
    payload["block_threshold"] = "not-an-int"
    with pytest.raises(ValueError):
        policy_from_bundle_payload(payload)
