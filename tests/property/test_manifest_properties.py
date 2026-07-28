from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from chitragupta.domain import (
    AdapterIdentity,
    BlastRadiusClassification,
    EffectManifest,
    Principal,
    PrincipalType,
    ReversibilityClassification,
    RiskClassification,
)

_now = datetime(2026, 1, 1, tzinfo=timezone.utc)

_safe_id = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), max_codepoint=122),
    min_size=1,
    max_size=40,
).filter(lambda s: s[0].isalnum())

_actor = Principal(principal_id="agent-1", principal_type=PrincipalType.AGENT)
_principal = Principal(principal_id="user-1", principal_type=PrincipalType.HUMAN)
_adapter = AdapterIdentity(adapter_id="test.adapter", adapter_version="1.0.0")


def _manifest(target_resource: str, nonce: str) -> EffectManifest:
    return EffectManifest(
        manifest_id="11111111-1111-4111-8111-111111111111",
        effect_type="test.effect",
        actor=_actor,
        principal=_principal,
        adapter=_adapter,
        target_resource=target_resource,
        parameters={},
        risk=RiskClassification.LOW,
        reversibility=ReversibilityClassification.REVERSIBLE,
        blast_radius=BlastRadiusClassification.SINGLE_RESOURCE,
        idempotency_key="idem-fixed",
        created_at=_now,
        expires_at=_now + timedelta(minutes=5),
        nonce=nonce,
    )


@given(_safe_id, _safe_id)
@settings(max_examples=200, deadline=None)
def test_changing_target_resource_changes_hash(target_a, target_b):
    assume(target_a != target_b)
    m1 = _manifest(target_a, "nonce-fixed")
    m2 = _manifest(target_b, "nonce-fixed")
    assert m1.canonical_hash() != m2.canonical_hash()


@given(_safe_id, _safe_id)
@settings(max_examples=200, deadline=None)
def test_changing_nonce_changes_hash(nonce_a, nonce_b):
    assume(nonce_a != nonce_b)
    m1 = _manifest("payment:beneficiary/X", nonce_a)
    m2 = _manifest("payment:beneficiary/X", nonce_b)
    assert m1.canonical_hash() != m2.canonical_hash()


@given(_safe_id)
@settings(max_examples=100, deadline=None)
def test_identical_construction_is_always_hash_stable(target_resource):
    m1 = _manifest(target_resource, "nonce-x")
    m2 = _manifest(target_resource, "nonce-x")
    assert m1.canonical_hash() == m2.canonical_hash()
    assert m1 == m2
