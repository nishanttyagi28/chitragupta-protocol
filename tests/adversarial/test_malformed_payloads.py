"""Adversarial/malformed payload tests across the core schemas.

These are deliberately hostile inputs: oversized fields, wrong types,
boundary-violating numbers, null bytes, and structurally invalid data.
Every one of them must be rejected at the schema boundary with a typed
error, never silently accepted or coerced into something unexpected.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from chitragupta.audit.events import AuditEvent
from chitragupta.canonical import CanonicalizationError, canonical_json_bytes
from chitragupta.domain import (
    AdapterIdentity,
    BlastRadiusClassification,
    MonetaryAmount,
    Principal,
    PrincipalType,
    ReversibilityClassification,
    RiskClassification,
    StateFingerprint,
    StateFingerprintKind,
)
from chitragupta.domain.manifest import EffectManifest
from chitragupta.grants.model import ExecutionGrant, ScopeConstraints

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_ACTOR = Principal(principal_id="agent-1", principal_type=PrincipalType.AGENT)
_PRINCIPAL = Principal(principal_id="user-1", principal_type=PrincipalType.HUMAN)
_ADAPTER = AdapterIdentity(adapter_id="test.adapter", adapter_version="1.0.0")


def _base_manifest_kwargs(**overrides):
    kwargs = {
        "manifest_id": "11111111-1111-4111-8111-111111111111",
        "effect_type": "test.effect",
        "actor": _ACTOR,
        "principal": _PRINCIPAL,
        "adapter": _ADAPTER,
        "target_resource": "resource/1",
        "parameters": {},
        "risk": RiskClassification.LOW,
        "reversibility": ReversibilityClassification.REVERSIBLE,
        "blast_radius": BlastRadiusClassification.SINGLE_RESOURCE,
        "idempotency_key": "idem-1",
        "created_at": _NOW,
        "expires_at": _NOW + timedelta(minutes=5),
        "nonce": "nonce-1",
    }
    kwargs.update(overrides)
    return kwargs


@pytest.mark.parametrize(
    "override",
    [
        {"target_resource": "x" * 100_000},
        {"target_resource": ""},
        {"manifest_id": ""},
        {"nonce": ""},
        {"idempotency_key": "x" * 1000},
        {"effect_type": "x" * 1000},
        {"parameters": {f"k{i}": i for i in range(1000)}},
        {"parameters": {"k": "v" * 100_000}},
        {"metadata": {f"k{i}": "v" for i in range(1000)}},
        {"risk": "not-a-real-risk-level"},
        {"reversibility": "sort-of-reversible"},
    ],
)
def test_manifest_rejects_adversarial_field_values(override):
    with pytest.raises(ValidationError):
        EffectManifest(**_base_manifest_kwargs(**override))


def test_manifest_rejects_null_byte_in_target_resource():
    with pytest.raises((ValidationError, ValueError)):
        EffectManifest(**_base_manifest_kwargs(target_resource="resource\x00/1"))


def test_manifest_rejects_negative_monetary_amount():
    with pytest.raises(ValidationError):
        MonetaryAmount(currency="INR", minor_units=-1)


def test_manifest_rejects_absurdly_large_monetary_amount():
    with pytest.raises(ValidationError):
        MonetaryAmount(currency="INR", minor_units=10**30)


def test_manifest_rejects_lowercase_currency():
    with pytest.raises(ValidationError):
        MonetaryAmount(currency="inr", minor_units=100)


def test_manifest_rejects_four_letter_currency():
    with pytest.raises(ValidationError):
        MonetaryAmount(currency="INRX", minor_units=100)


def test_state_fingerprint_rejects_empty_value():
    with pytest.raises(ValidationError):
        StateFingerprint(kind=StateFingerprintKind.ROW_VERSION, value="")


def test_state_fingerprint_rejects_oversized_value():
    with pytest.raises(ValidationError):
        StateFingerprint(kind=StateFingerprintKind.ROW_VERSION, value="x" * 10_000)


def _base_grant_kwargs(**overrides):
    kwargs = {
        "grant_id": "g1",
        "manifest_hash": "sha256:" + "a" * 64,
        "issuer": _PRINCIPAL,
        "subject": _ACTOR,
        "audience": ("adapter.x",),
        "allowed_effect_types": ("effect.x",),
        "scope": ScopeConstraints(),
        "issued_at": _NOW,
        "not_before": _NOW,
        "expires_at": _NOW + timedelta(minutes=5),
        "nonce": "n1",
        "key_id": "k1",
        "signature": "sig",
    }
    kwargs.update(overrides)
    return kwargs


@pytest.mark.parametrize(
    "override",
    [
        {"manifest_hash": "not-a-hash"},
        {"manifest_hash": "sha256:tooshort"},
        {"manifest_hash": "md5:" + "a" * 32},
        {"max_uses": 0},
        {"max_uses": -1},
        {"audience": ()},
        {"allowed_effect_types": ()},
        {"grant_id": ""},
        {"nonce": ""},
        {"key_id": "x" * 1000},
    ],
)
def test_grant_rejects_adversarial_field_values(override):
    with pytest.raises(ValidationError):
        ExecutionGrant(**_base_grant_kwargs(**override))


def test_grant_rejects_expires_before_not_before():
    with pytest.raises(ValidationError):
        ExecutionGrant(
            **_base_grant_kwargs(not_before=_NOW, expires_at=_NOW - timedelta(seconds=1))
        )


def test_scope_constraints_rejects_empty_explicit_allow_lists():
    for field in ("target_resources", "recipients", "allowed_fields", "environments"):
        with pytest.raises(ValidationError):
            ScopeConstraints(**{field: ()})


@pytest.mark.parametrize(
    "override",
    [
        {"sequence": 0},
        {"sequence": -5},
        {"event_id": ""},
    ],
)
def test_audit_event_rejects_adversarial_values(override):
    kwargs = {
        "sequence": 1,
        "event_id": "e1",
        "previous_hash": None,
        "timestamp": _NOW,
        "event_type": "x",
        "decision": "allowed",
    }
    kwargs.update(override)
    with pytest.raises(ValidationError):
        AuditEvent(**kwargs)


def test_audit_event_rejects_oversized_metadata_value():
    with pytest.raises(ValidationError):
        AuditEvent(
            sequence=1,
            event_id="e1",
            previous_hash=None,
            timestamp=_NOW,
            event_type="x",
            decision="allowed",
            metadata={"k": "v" * 10_000},
        )


@pytest.mark.parametrize(
    "value",
    [
        object(),
        {"nested": object()},
        [1, 2, {"bad": object()}],
        {1, 2, 3},  # sets are not JSON-representable
        b"raw bytes",
    ],
)
def test_canonicalization_rejects_non_json_types(value):
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes(value)


def test_canonicalization_rejects_nan_and_infinity():
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"x": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"x": float("inf")})
