from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from chitragupta.domain import EffectManifest
from chitragupta.errors import SchemaVersionError
from chitragupta.protocol.versioning import assert_supported_schema_version


def test_manifest_canonical_hash_is_deterministic(manifest_factory):
    m1 = manifest_factory()
    m2 = manifest_factory()
    assert m1.canonical_hash() == m2.canonical_hash()


def test_manifest_hash_changes_with_any_security_field(manifest_factory):
    base = manifest_factory()
    variants = [
        manifest_factory(target_resource="payment:beneficiary/Y"),
        manifest_factory(amount_minor_units=150001),
        manifest_factory(effect_type="payment.refund"),
        manifest_factory(nonce="different-nonce"),
        manifest_factory(idempotency_key="different-idem"),
        manifest_factory(ttl_seconds=301),
    ]
    base_hash = base.canonical_hash()
    for v in variants:
        assert v.canonical_hash() != base_hash


def test_manifest_is_immutable(manifest_factory):
    m = manifest_factory()
    with pytest.raises(ValidationError):
        m.target_resource = "payment:beneficiary/other"  # type: ignore[misc]


def test_manifest_rejects_unknown_fields(
    manifest_factory, now, agent_principal, human_principal, adapter_identity
):
    with pytest.raises(ValidationError):
        EffectManifest(
            manifest_id="m1",
            effect_type="payment.transfer",
            actor=agent_principal,
            principal=human_principal,
            adapter=adapter_identity,
            target_resource="payment:beneficiary/X",
            parameters={},
            risk="high",
            reversibility="compensatable",
            blast_radius="single_resource",
            idempotency_key="idem",
            created_at=now,
            expires_at=now + timedelta(seconds=1),
            nonce="n",
            unknown_field="should not be allowed",  # type: ignore[call-arg]
        )


def test_manifest_rejects_naive_datetime(now, agent_principal, human_principal, adapter_identity):
    naive = now.replace(tzinfo=None)
    with pytest.raises(ValidationError):
        EffectManifest(
            manifest_id="m1",
            effect_type="payment.transfer",
            actor=agent_principal,
            principal=human_principal,
            adapter=adapter_identity,
            target_resource="payment:beneficiary/X",
            parameters={},
            risk="high",
            reversibility="compensatable",
            blast_radius="single_resource",
            idempotency_key="idem",
            created_at=naive,
            expires_at=naive + timedelta(seconds=1),
            nonce="n",
        )


def test_manifest_rejects_expiry_before_creation(manifest_factory, now):
    with pytest.raises(ValidationError):
        manifest_factory(ttl_seconds=-10)


def test_manifest_rejects_oversized_metadata(
    manifest_factory, now, agent_principal, human_principal, adapter_identity
):
    with pytest.raises(ValidationError):
        EffectManifest(
            manifest_id="m1",
            effect_type="payment.transfer",
            actor=agent_principal,
            principal=human_principal,
            adapter=adapter_identity,
            target_resource="payment:beneficiary/X",
            parameters={},
            risk="high",
            reversibility="compensatable",
            blast_radius="single_resource",
            idempotency_key="idem",
            created_at=now,
            expires_at=now + timedelta(seconds=1),
            nonce="n",
            metadata={f"k{i}": "v" for i in range(100)},
        )


def test_manifest_rejects_float_parameter(manifest_factory):
    with pytest.raises(ValidationError):
        manifest_factory(parameters={"amount": 1.5})


def test_manifest_rejects_too_many_parameters(manifest_factory):
    with pytest.raises(ValidationError):
        manifest_factory(parameters={f"k{i}": i for i in range(100)})


def test_schema_version_rejection_unknown_major():
    with pytest.raises(SchemaVersionError):
        assert_supported_schema_version("99.0")


def test_schema_version_accepts_current_major():
    assert_supported_schema_version("1.0")
    assert_supported_schema_version("1.7")


def test_schema_version_rejects_malformed():
    with pytest.raises(SchemaVersionError):
        assert_supported_schema_version("garbage")


def test_schema_version_rejects_non_digit_minor():
    with pytest.raises(SchemaVersionError):
        assert_supported_schema_version("1.x")
