"""Build compensation EffectManifests bound to an original sealed effect.

A compensation effect is a *separate* consequential action: it has its own
manifest hash, seal, and grant. It must cryptographically bind the original
manifest's canonical hash so a grant authorized for compensating A can never
be applied to B.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from karmasakshi.adapters.base import CommitResult
from karmasakshi.config.clock import SYSTEM_CLOCK, Clock, ensure_utc
from karmasakshi.domain.enums import (
    BlastRadiusClassification,
    ReversibilityClassification,
    RiskClassification,
)
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.errors import CompensationBindingError

ORIGINAL_HASH_PARAM = "original_manifest_hash"
ORIGINAL_ID_PARAM = "original_manifest_id"
ORIGINAL_COMMIT_REF_PARAM = "original_provider_reference"
COMPENSATION_EFFECT_SUFFIX = ".compensate"


def assert_sha256_digest(value: str, *, field: str) -> str:
    if not value.startswith("sha256:") or len(value) != len("sha256:") + 64:
        raise CompensationBindingError(f"{field} must be a sha256:<hex> digest")
    return value


def build_compensation_manifest(
    *,
    original: SealedManifest,
    original_commit: CommitResult | None = None,
    effect_type: str | None = None,
    parameters: dict[str, str | int | bool | None] | None = None,
    target_resource: str | None = None,
    risk: RiskClassification | None = None,
    reversibility: ReversibilityClassification = ReversibilityClassification.COMPENSATABLE,
    blast_radius: BlastRadiusClassification | None = None,
    idempotency_key: str | None = None,
    manifest_id: str | None = None,
    nonce: str | None = None,
    ttl_seconds: int = 300,
    clock: Clock = SYSTEM_CLOCK,
    created_at: datetime | None = None,
) -> EffectManifest:
    """Construct an unsealed compensation ``EffectManifest``.

    Always binds ``original_manifest_hash`` (and ``original_manifest_id``)
    into ``parameters`` so they participate in ``canonical_hash()``.
    """
    original.verify_integrity()
    original_hash = original.seal.manifest_hash
    assert_sha256_digest(original_hash, field="original_manifest_hash")

    base_params: dict[str, str | int | bool | None] = dict(parameters or {})
    if ORIGINAL_HASH_PARAM in base_params and base_params[ORIGINAL_HASH_PARAM] != original_hash:
        raise CompensationBindingError(
            f"parameters[{ORIGINAL_HASH_PARAM!r}] conflicts with sealed original hash"
        )
    base_params[ORIGINAL_HASH_PARAM] = original_hash
    base_params[ORIGINAL_ID_PARAM] = original.manifest.manifest_id
    if original_commit is not None and original_commit.provider_reference:
        base_params[ORIGINAL_COMMIT_REF_PARAM] = original_commit.provider_reference

    when = ensure_utc(created_at) if created_at is not None else clock.now()
    comp_effect = effect_type or f"{original.manifest.effect_type}{COMPENSATION_EFFECT_SUFFIX}"
    return EffectManifest(
        manifest_id=manifest_id or str(uuid.uuid4()),
        effect_type=comp_effect,
        actor=original.manifest.actor,
        principal=original.manifest.principal,
        adapter=original.manifest.adapter,
        target_resource=target_resource or original.manifest.target_resource,
        parameters=base_params,
        risk=risk or original.manifest.risk,
        reversibility=reversibility,
        blast_radius=blast_radius or original.manifest.blast_radius,
        estimated_cost=original.manifest.estimated_cost,
        idempotency_key=idempotency_key
        or f"compensate:{original.manifest.idempotency_key}:{uuid.uuid4().hex[:12]}",
        created_at=when,
        expires_at=when + timedelta(seconds=ttl_seconds),
        nonce=nonce or uuid.uuid4().hex,
        parent_manifest_id=original.manifest.manifest_id,
        metadata={
            "compensation_of": original.manifest.manifest_id,
            "compensation_of_hash": original_hash,
        },
    )


def original_manifest_hash_of(manifest: EffectManifest) -> str:
    """Extract the bound original hash from a compensation manifest."""
    raw = manifest.parameters.get(ORIGINAL_HASH_PARAM)
    if not isinstance(raw, str):
        raise CompensationBindingError(
            f"compensation manifest {manifest.manifest_id} is missing "
            f"parameters[{ORIGINAL_HASH_PARAM!r}]"
        )
    return assert_sha256_digest(raw, field=ORIGINAL_HASH_PARAM)


def assert_compensation_binds_original(
    compensation: EffectManifest | SealedManifest,
    original: SealedManifest,
) -> None:
    """Raise if ``compensation`` is not bound to ``original``'s sealed hash."""
    manifest = compensation.manifest if isinstance(compensation, SealedManifest) else compensation
    if isinstance(compensation, SealedManifest):
        compensation.verify_integrity()
    original.verify_integrity()
    bound = original_manifest_hash_of(manifest)
    if bound != original.seal.manifest_hash:
        raise CompensationBindingError(
            f"compensation manifest {manifest.manifest_id} is bound to {bound}, "
            f"but original sealed hash is {original.seal.manifest_hash}"
        )
    if manifest.parent_manifest_id not in (None, original.manifest.manifest_id):
        raise CompensationBindingError(
            f"compensation parent_manifest_id {manifest.parent_manifest_id!r} "
            f"does not match original {original.manifest.manifest_id!r}"
        )


__all__ = [
    "COMPENSATION_EFFECT_SUFFIX",
    "ORIGINAL_COMMIT_REF_PARAM",
    "ORIGINAL_HASH_PARAM",
    "ORIGINAL_ID_PARAM",
    "assert_compensation_binds_original",
    "assert_sha256_digest",
    "build_compensation_manifest",
    "original_manifest_hash_of",
]
