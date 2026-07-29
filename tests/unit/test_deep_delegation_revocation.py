"""Tests for deep delegation revocation (Phase 11)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.delegation import assert_no_revoked_ancestors
from karmasakshi.errors import DelegationLineageError, GrantRevokedError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.stores.memory import InMemoryGrantStore


def _authorize_root(engine, sealed, issuer_signing_key, human_principal, agent_principal, now):
    return engine.authorize(
        sealed,
        issuer=human_principal,
        subject=agent_principal,
        audience=(sealed.manifest.adapter.adapter_id,),
        allowed_effect_types=(sealed.manifest.effect_type,),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        signing_key=issuer_signing_key,
    )


def test_grandparent_revocation_blocks_grandchild_commit(
    engine_factory,
    manifest_factory,
    fake_adapter,
    issuer_signing_key,
    human_principal,
    agent_principal,
    fixed_clock,
):
    engine = engine_factory()
    now = fixed_clock.now()
    prepared = engine.prepare(fake_adapter, manifest_factory(), context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    root = _authorize_root(
        engine, sealed, issuer_signing_key, human_principal, agent_principal, now
    )
    mid = engine.delegate(
        root,
        issuer=human_principal,
        subject=agent_principal,
        signing_key=issuer_signing_key,
        grant_id="mid-grant",
        max_uses=1,
        manifest_hash=sealed.seal.manifest_hash,
    )
    leaf = engine.delegate(
        mid,
        issuer=human_principal,
        subject=agent_principal,
        signing_key=issuer_signing_key,
        grant_id="leaf-grant",
        max_uses=1,
        manifest_hash=sealed.seal.manifest_hash,
    )
    engine.revoke(root, sealed.manifest.manifest_id, revoked_by=human_principal)

    with pytest.raises(GrantRevokedError, match="ancestor"):
        engine.commit(sealed, leaf, fake_adapter, context=None)


def test_lineage_unknown_fails_closed_for_delegated_grant(now, issuer_signing_key, human_principal):
    store = InMemoryGrantStore()
    from karmasakshi.grants.issuer import issue_grant

    root = issue_grant(
        grant_id="r1",
        issuer=human_principal,
        subject=human_principal,
        audience=("payment.simulator",),
        allowed_effect_types=("payment.transfer",),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        nonce="n1",
        signing_key=issuer_signing_key,
        manifest_hash="sha256:" + "1" * 64,
        parent_grant_id=None,
    )
    child = issue_grant(
        grant_id="c1",
        issuer=human_principal,
        subject=human_principal,
        audience=("payment.simulator",),
        allowed_effect_types=("payment.transfer",),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        nonce="n2",
        signing_key=issuer_signing_key,
        manifest_hash="sha256:" + "1" * 64,
        parent_grant_id=root.grant_id,
    )
    # Only child lineage recorded; parent has no lineage row -> uncertain
    store.record_lineage(child.grant_id, root.grant_id)
    with pytest.raises(DelegationLineageError, match="lineage unknown"):
        assert_no_revoked_ancestors(child, store)


def test_assert_no_revoked_ancestors_clears_recorded_chain(
    now, issuer_signing_key, human_principal
):
    store = InMemoryGrantStore()
    from karmasakshi.grants.issuer import issue_grant

    mh = "sha256:" + "2" * 64
    root = issue_grant(
        grant_id="r2",
        issuer=human_principal,
        subject=human_principal,
        audience=("a",),
        allowed_effect_types=("e",),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        nonce="n1",
        signing_key=issuer_signing_key,
        manifest_hash=mh,
    )
    mid = issue_grant(
        grant_id="m2",
        issuer=human_principal,
        subject=human_principal,
        audience=("a",),
        allowed_effect_types=("e",),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        nonce="n2",
        signing_key=issuer_signing_key,
        manifest_hash=mh,
        parent_grant_id=root.grant_id,
    )
    leaf = issue_grant(
        grant_id="l2",
        issuer=human_principal,
        subject=human_principal,
        audience=("a",),
        allowed_effect_types=("e",),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        nonce="n3",
        signing_key=issuer_signing_key,
        manifest_hash=mh,
        parent_grant_id=mid.grant_id,
    )
    store.record_lineage(root.grant_id, None)
    store.record_lineage(mid.grant_id, root.grant_id)
    store.record_lineage(leaf.grant_id, mid.grant_id)
    checked = assert_no_revoked_ancestors(leaf, store)
    assert checked == (mid.grant_id, root.grant_id)
