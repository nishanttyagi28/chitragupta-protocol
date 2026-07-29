"""Build a portable Evidence Pack from one engine run's artifacts."""

from __future__ import annotations

from karmasakshi.audit.journal import AuditJournal
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.errors import EvidencePackAssemblyError, EvidencePackTooLargeError
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.passports.v2 import ActionPassportV2
from karmasakshi.portable.model import (
    MAX_EMBEDDED_AUDIT_EVENTS,
    MAX_EMBEDDED_KEYS,
    EmbeddedVerificationKey,
    EvidencePack,
)


def build_evidence_pack(
    *,
    passport: ActionPassportV2,
    sealed_manifest: SealedManifest,
    audit: AuditJournal,
    keyring: Keyring,
    grant: ExecutionGrant | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> EvidencePack:
    """Assemble an :class:`EvidencePack` for ``sealed_manifest``.

    ``keyring`` is embedded as public-only material (never private keys):
    every currently trusted key is copied in, so a recipient can
    independently re-verify the seal and grant signatures without contacting
    the issuing system. Rotated-out keys removed from the keyring before
    this call will not be embedded -- see docs/portable-evidence.md's
    "Known limitations".
    """
    manifest_id = sealed_manifest.manifest.manifest_id
    if passport.manifest_id != manifest_id:
        raise EvidencePackAssemblyError(
            f"passport.manifest_id ({passport.manifest_id!r}) does not match "
            f"sealed_manifest.manifest.manifest_id ({manifest_id!r})"
        )
    if (
        grant is not None
        and grant.manifest_hash is not None
        and grant.manifest_hash != sealed_manifest.seal.manifest_hash
    ):
        raise EvidencePackAssemblyError(
            f"grant.manifest_hash ({grant.manifest_hash!r}) does not match "
            f"the sealed manifest hash ({sealed_manifest.seal.manifest_hash!r})"
        )

    events = tuple(audit.events_for_manifest(manifest_id))
    if len(events) > MAX_EMBEDDED_AUDIT_EVENTS:
        raise EvidencePackTooLargeError(
            f"manifest {manifest_id} has {len(events)} audit events; "
            f"an evidence pack embeds at most {MAX_EMBEDDED_AUDIT_EVENTS}"
        )

    key_ids = keyring.key_ids()
    if len(key_ids) > MAX_EMBEDDED_KEYS:
        raise EvidencePackTooLargeError(
            f"keyring has {len(key_ids)} keys; an evidence pack embeds at most {MAX_EMBEDDED_KEYS}"
        )
    embedded_keys = tuple(
        EmbeddedVerificationKey(
            key_id=key_id,
            algorithm=keyring.get(key_id).algorithm,
            public_key_b64=keyring.get(key_id).public_bytes_b64(),
        )
        for key_id in key_ids
    )

    draft = EvidencePack(
        generated_at=clock.now(),
        pack_hash="sha256:" + ("0" * 64),
        manifest_id=manifest_id,
        passport=passport,
        sealed_manifest=sealed_manifest,
        grant=grant,
        audit_events=events,
        verification_keys=embedded_keys,
    )
    return draft.model_copy(update={"pack_hash": draft.compute_pack_hash()})


__all__ = ["build_evidence_pack"]
