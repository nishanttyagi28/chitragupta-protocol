"""Fully offline verification of a portable Evidence Pack (extreme-v2 Phase 24).

Every check here uses only what the pack itself carries -- no live
keyring, store, or audit journal is consulted. That is the entire point:
a recipient who only has this one JSON document can independently redo
the same structural and cryptographic checks the issuing system made.

What this does **not** prove (see docs/portable-evidence.md):

- That the embedded audit events are the *complete* history for this
  manifest, or that nothing was omitted from the pack -- only that the
  events present are individually untampered and consistently ordered
  (:func:`karmasakshi.audit.journal.verify_event_self_consistency`).
- That the embedded verification keys are still trusted *now* -- a key
  revoked after the pack was generated will still verify here; recipients
  who need current trust status must cross-check ``key_id`` against a
  live keyring, not this pack alone.
- Anything about lifecycle state *after* the pack was generated.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from karmasakshi.audit.journal import verify_event_self_consistency
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import VerificationKey
from karmasakshi.errors import KarmaSakshiError
from karmasakshi.grants.verifier import verify_grant_signature
from karmasakshi.portable.model import EvidencePack
from karmasakshi.protocol.sealing import verify_seal


class EvidencePackVerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_hash_verified: bool
    passport_hash_verified: bool
    seal_verified: bool
    grant_verified: bool
    audit_events_self_consistent: bool
    audit_events_match_manifest: bool
    manifest_hash_consistent: bool
    all_verified: bool
    reasons: tuple[str, ...] = ()


def _embedded_keyring(pack: EvidencePack) -> Keyring:
    return Keyring(
        [
            VerificationKey.from_public_b64(k.key_id, k.public_key_b64, k.algorithm)
            for k in pack.verification_keys
        ]
    )


def verify_evidence_pack(pack: EvidencePack) -> EvidencePackVerificationResult:
    """Independently re-verify every checkable fact in ``pack`` using only
    its own embedded contents."""
    reasons: list[str] = []

    pack_hash_verified = pack.compute_pack_hash() == pack.pack_hash
    if not pack_hash_verified:
        reasons.append("pack_hash: recomputed hash does not match stored pack_hash")

    passport_hash_verified = True
    try:
        pack.passport.verify_passport_hash()
    except KarmaSakshiError as exc:
        passport_hash_verified = False
        reasons.append(f"passport_hash: {exc}")

    keyring: Keyring | None
    try:
        keyring = _embedded_keyring(pack)
    except (KarmaSakshiError, ValueError) as exc:
        # A pack is untrusted external input: a malformed embedded key
        # (bad base64, wrong-length bytes) must fail verification, never
        # crash the verifier.
        keyring = None
        reasons.append(f"verification_keys: {exc}")

    seal_verified = False
    grant_verified = pack.grant is None
    if keyring is not None:
        try:
            verify_seal(pack.sealed_manifest, keyring)
            seal_verified = True
        except KarmaSakshiError as exc:
            reasons.append(f"seal: {exc}")

        if pack.grant is not None:
            try:
                verify_grant_signature(pack.grant, keyring)
                grant_verified = True
            except KarmaSakshiError as exc:
                reasons.append(f"grant: {exc}")
    else:
        reasons.append("seal: cannot verify, embedded verification_keys were unparseable")

    audit_events_self_consistent = True
    try:
        verify_event_self_consistency(pack.audit_events)
    except KarmaSakshiError as exc:
        audit_events_self_consistent = False
        reasons.append(f"audit_events: {exc}")

    audit_events_match_manifest = all(
        event.manifest_id == pack.manifest_id
        for event in pack.audit_events
        if event.manifest_id is not None
    )
    if not audit_events_match_manifest:
        reasons.append("audit_events: contains an event for a different manifest_id")

    manifest_hash_consistent = (
        pack.sealed_manifest.seal.manifest_hash == pack.passport.manifest_hash
    )
    if pack.grant is not None and pack.grant.manifest_hash is not None:
        manifest_hash_consistent = (
            manifest_hash_consistent
            and pack.grant.manifest_hash == pack.sealed_manifest.seal.manifest_hash
        )
    if not manifest_hash_consistent:
        reasons.append(
            "manifest_hash: sealed manifest, passport, and/or grant reference "
            "different manifest hashes"
        )

    all_verified = (
        pack_hash_verified
        and passport_hash_verified
        and seal_verified
        and grant_verified
        and audit_events_self_consistent
        and audit_events_match_manifest
        and manifest_hash_consistent
    )

    return EvidencePackVerificationResult(
        pack_hash_verified=pack_hash_verified,
        passport_hash_verified=passport_hash_verified,
        seal_verified=seal_verified,
        grant_verified=grant_verified,
        audit_events_self_consistent=audit_events_self_consistent,
        audit_events_match_manifest=audit_events_match_manifest,
        manifest_hash_consistent=manifest_hash_consistent,
        all_verified=all_verified,
        reasons=tuple(reasons),
    )


__all__ = ["EvidencePackVerificationResult", "verify_evidence_pack"]
