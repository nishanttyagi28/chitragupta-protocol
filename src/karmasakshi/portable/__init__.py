"""Portable Evidence Packs: a self-contained, offline-verifiable bundle
binding one manifest's Action Passport, sealed manifest, grant, audit
slice, and verification keys together (extreme-v2 Phase 24).

See docs/portable-evidence.md.
"""

from __future__ import annotations

from karmasakshi.portable.builder import build_evidence_pack
from karmasakshi.portable.model import (
    EVIDENCE_PACK_FORMAT,
    EVIDENCE_PACK_SCHEMA_VERSION,
    EmbeddedVerificationKey,
    EvidencePack,
)
from karmasakshi.portable.verify import EvidencePackVerificationResult, verify_evidence_pack

__all__ = [
    "EVIDENCE_PACK_FORMAT",
    "EVIDENCE_PACK_SCHEMA_VERSION",
    "EmbeddedVerificationKey",
    "EvidencePack",
    "EvidencePackVerificationResult",
    "build_evidence_pack",
    "verify_evidence_pack",
]
