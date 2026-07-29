"""Sealing and verifying policy bundles -- mirrors ``protocol/sealing.py``
exactly, one layer up: signing binds a signer to a policy bundle's
canonical hash; verification recomputes the hash independently (tamper
detection), checks the signature (identity proof), and checks the
bundle's effective window and, optionally, its declared policy type.
"""

from __future__ import annotations

from datetime import datetime

from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey
from karmasakshi.errors import (
    PolicyBundleExpiredError,
    PolicyBundleNotYetEffectiveError,
    PolicyBundleTypeMismatchError,
)
from karmasakshi.policy.bundle import PolicyBundle, PolicyBundleSeal, SealedPolicyBundle


def seal_policy_bundle(
    bundle: PolicyBundle,
    signing_key: SigningKey,
    clock: Clock = SYSTEM_CLOCK,
) -> SealedPolicyBundle:
    """Sign ``bundle``'s canonical hash, producing a :class:`SealedPolicyBundle`."""
    bundle_hash = bundle.canonical_hash()
    signature = signing_key.sign(bundle_hash.encode("utf-8"))
    seal = PolicyBundleSeal(
        algorithm=signing_key.algorithm,
        key_id=signing_key.key_id,
        bundle_hash=bundle_hash,
        signature=signature,
        sealed_at=clock.now(),
    )
    return SealedPolicyBundle(bundle=bundle, seal=seal)


def verify_policy_bundle(
    sealed: SealedPolicyBundle,
    keyring: Keyring,
    *,
    now: datetime,
    expected_policy_type: str | None = None,
) -> None:
    """Verify a sealed policy bundle end-to-end.

    Raises :class:`~karmasakshi.errors.PolicyBundleTamperedError` if the
    bundle was mutated after sealing,
    :class:`~karmasakshi.errors.UnknownKeyError` if the seal references a
    key not in ``keyring``,
    :class:`~karmasakshi.errors.InvalidSignatureError` if the signature
    does not verify, :class:`~karmasakshi.errors.PolicyBundleTypeMismatchError`
    if ``expected_policy_type`` is given and does not match, and
    :class:`~karmasakshi.errors.PolicyBundleNotYetEffectiveError` /
    :class:`~karmasakshi.errors.PolicyBundleExpiredError` if ``now`` falls
    outside the bundle's effective window.
    """
    sealed.verify_integrity()
    keyring.verify(
        sealed.seal.key_id, sealed.seal.bundle_hash.encode("utf-8"), sealed.seal.signature
    )
    if expected_policy_type is not None and sealed.bundle.policy_type != expected_policy_type:
        raise PolicyBundleTypeMismatchError(
            f"policy bundle {sealed.bundle.bundle_id} has policy_type "
            f"{sealed.bundle.policy_type!r}, expected {expected_policy_type!r}"
        )
    if now < sealed.bundle.effective_from:
        raise PolicyBundleNotYetEffectiveError(
            f"policy bundle {sealed.bundle.bundle_id} is not effective until "
            f"{sealed.bundle.effective_from.isoformat()} (now={now.isoformat()})"
        )
    if sealed.bundle.effective_until is not None and now >= sealed.bundle.effective_until:
        raise PolicyBundleExpiredError(
            f"policy bundle {sealed.bundle.bundle_id} expired at "
            f"{sealed.bundle.effective_until.isoformat()} (now={now.isoformat()})"
        )


__all__ = ["seal_policy_bundle", "verify_policy_bundle"]
