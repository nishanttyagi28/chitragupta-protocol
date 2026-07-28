from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.delegation import (
    assert_grant_narrower_or_equal,
    assert_scope_narrower_or_equal,
    verify_delegation_chain,
)
from karmasakshi.domain.common import MonetaryAmount
from karmasakshi.errors import (
    ConstraintWideningError,
    GrantRevokedError,
    IncomparableConstraintError,
)
from karmasakshi.grants.issuer import issue_grant
from karmasakshi.grants.model import ScopeConstraints


def _base_grant(now, issuer, subject, signing_key, **overrides):
    kwargs = {
        "grant_id": "parent-1",
        "issuer": issuer,
        "subject": subject,
        "audience": ("payment.simulator",),
        "allowed_effect_types": ("payment.refund",),
        "scope": ScopeConstraints(
            recipients=("merchant-A",),
            max_amount=MonetaryAmount(currency="INR", minor_units=500000),
        ),
        "not_before": now,
        "expires_at": now + timedelta(hours=1),
        "nonce": "parent-nonce-1",
        "signing_key": signing_key,
    }
    kwargs.update(overrides)
    return issue_grant(**kwargs)


# --- scope-level attenuation ------------------------------------------------


def test_narrower_scope_is_accepted():
    parent = ScopeConstraints(
        recipients=("merchant-A",), max_amount=MonetaryAmount(currency="INR", minor_units=500000)
    )
    child = ScopeConstraints(
        recipients=("merchant-A",), max_amount=MonetaryAmount(currency="INR", minor_units=150000)
    )
    assert_scope_narrower_or_equal(child, parent)  # must not raise


def test_equal_scope_is_accepted():
    scope = ScopeConstraints(recipients=("merchant-A",))
    assert_scope_narrower_or_equal(scope, scope)


def test_wider_amount_rejected():
    parent = ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=500000))
    child = ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=700000))
    with pytest.raises(ConstraintWideningError):
        assert_scope_narrower_or_equal(child, parent)


def test_wider_recipient_rejected():
    parent = ScopeConstraints(recipients=("merchant-A",))
    child = ScopeConstraints(recipients=("merchant-B",))
    with pytest.raises(ConstraintWideningError):
        assert_scope_narrower_or_equal(child, parent)


def test_child_cannot_go_unrestricted_when_parent_restricts():
    parent = ScopeConstraints(recipients=("merchant-A",))
    child = ScopeConstraints(recipients=None)
    with pytest.raises(ConstraintWideningError):
        assert_scope_narrower_or_equal(child, parent)


def test_incomparable_currency_rejected():
    parent = ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=500000))
    child = ScopeConstraints(max_amount=MonetaryAmount(currency="USD", minor_units=100))
    with pytest.raises(IncomparableConstraintError):
        assert_scope_narrower_or_equal(child, parent)


def test_parent_unrestricted_allows_any_child_value():
    parent = ScopeConstraints()  # all None = unrestricted
    child = ScopeConstraints(
        recipients=("merchant-A",), max_amount=MonetaryAmount(currency="INR", minor_units=1)
    )
    assert_scope_narrower_or_equal(child, parent)  # must not raise


def test_child_amount_cannot_go_unrestricted_when_parent_caps_it():
    parent = ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=500000))
    child = ScopeConstraints(max_amount=None)
    with pytest.raises(ConstraintWideningError):
        assert_scope_narrower_or_equal(child, parent)


# --- grant-level attenuation -------------------------------------------------


def test_grant_expiry_cannot_outlive_parent(
    now, human_principal, agent_principal, issuer_signing_key
):
    parent = _base_grant(now, human_principal, agent_principal, issuer_signing_key)
    child = _base_grant(
        now,
        human_principal,
        agent_principal,
        issuer_signing_key,
        grant_id="child-1",
        nonce="child-nonce-1",
        expires_at=now + timedelta(hours=2),  # outlives parent's 1-hour window
        parent_grant_id=parent.grant_id,
    )
    with pytest.raises(ConstraintWideningError):
        assert_grant_narrower_or_equal(child, parent)


def test_grant_not_before_cannot_start_earlier_than_parent(
    now, human_principal, agent_principal, issuer_signing_key
):
    parent = _base_grant(now, human_principal, agent_principal, issuer_signing_key)
    child = _base_grant(
        now,
        human_principal,
        agent_principal,
        issuer_signing_key,
        grant_id="child-1",
        nonce="child-nonce-1",
        not_before=now - timedelta(minutes=10),  # starts before parent's window opens
        parent_grant_id=parent.grant_id,
    )
    with pytest.raises(ConstraintWideningError):
        assert_grant_narrower_or_equal(child, parent)


def test_grant_max_uses_cannot_exceed_parent(
    now, human_principal, agent_principal, issuer_signing_key
):
    parent = _base_grant(now, human_principal, agent_principal, issuer_signing_key, max_uses=1)
    child = _base_grant(
        now,
        human_principal,
        agent_principal,
        issuer_signing_key,
        grant_id="child-1",
        nonce="child-nonce-1",
        max_uses=5,
        parent_grant_id=parent.grant_id,
    )
    with pytest.raises(ConstraintWideningError):
        assert_grant_narrower_or_equal(child, parent)


def test_valid_narrower_child_grant_accepted(
    now, human_principal, agent_principal, issuer_signing_key
):
    parent = _base_grant(now, human_principal, agent_principal, issuer_signing_key)
    child = _base_grant(
        now,
        human_principal,
        agent_principal,
        issuer_signing_key,
        grant_id="child-1",
        nonce="child-nonce-1",
        expires_at=now + timedelta(minutes=30),
        scope=ScopeConstraints(
            recipients=("merchant-A",),
            max_amount=MonetaryAmount(currency="INR", minor_units=150000),
        ),
        parent_grant_id=parent.grant_id,
    )
    assert_grant_narrower_or_equal(child, parent)  # must not raise


# --- engine.delegate() ---------------------------------------------------


def test_engine_delegate_narrower_child_succeeds(
    engine_factory,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    parent = _base_grant(now, human_principal, agent_principal, issuer_signing_key)
    child = engine.delegate(
        parent,
        issuer=human_principal,
        subject=agent_principal,
        signing_key=issuer_signing_key,
        grant_id="child-narrow-1",
        nonce="child-narrow-nonce-1",
        scope=ScopeConstraints(
            recipients=("merchant-A",),
            max_amount=MonetaryAmount(currency="INR", minor_units=150000),
        ),
    )
    assert child.parent_grant_id == parent.grant_id
    assert child.scope.max_amount.minor_units == 150000


def test_engine_delegate_wider_amount_rejected(
    engine_factory,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    parent = _base_grant(now, human_principal, agent_principal, issuer_signing_key)
    with pytest.raises(ConstraintWideningError):
        engine.delegate(
            parent,
            issuer=human_principal,
            subject=agent_principal,
            signing_key=issuer_signing_key,
            grant_id="child-wide-1",
            nonce="child-wide-nonce-1",
            scope=ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=700000)),
        )


def test_engine_delegate_longer_expiry_rejected(
    engine_factory,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    parent = _base_grant(now, human_principal, agent_principal, issuer_signing_key)
    with pytest.raises(ConstraintWideningError):
        engine.delegate(
            parent,
            issuer=human_principal,
            subject=agent_principal,
            signing_key=issuer_signing_key,
            grant_id="child-late-1",
            nonce="child-late-nonce-1",
            expires_at=now + timedelta(hours=2),
        )


def test_engine_delegate_inherits_parent_fields_when_unspecified(
    engine_factory,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    engine = engine_factory()
    parent = _base_grant(now, human_principal, agent_principal, issuer_signing_key)
    child = engine.delegate(
        parent,
        issuer=human_principal,
        subject=agent_principal,
        signing_key=issuer_signing_key,
        grant_id="child-inherit-1",
        nonce="child-inherit-nonce-1",
    )
    assert child.expires_at == parent.expires_at
    assert child.scope == parent.scope
    assert child.audience == parent.audience


def test_parent_revocation_blocks_delegated_child_at_commit(
    engine_factory,
    manifest_factory,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    engine = engine_factory()
    manifest = manifest_factory(manifest_id="deleg-1", effect_type="payment.refund")
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)

    parent = _base_grant(now, human_principal, agent_principal, issuer_signing_key)
    child = engine.delegate(
        parent,
        issuer=human_principal,
        subject=agent_principal,
        signing_key=issuer_signing_key,
        grant_id="child-revoke-1",
        nonce="child-revoke-nonce-1",
        manifest_hash=sealed.seal.manifest_hash,
    )

    engine.context.grant_store.revoke(parent.grant_id)
    with pytest.raises(GrantRevokedError):
        engine.commit(sealed, child, fake_adapter, context=None)


# --- multi-hop chain verification -----------------------------------------


def test_verify_delegation_chain_accepts_valid_chain(
    keyring,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    from karmasakshi.stores.memory import InMemoryGrantStore

    store = InMemoryGrantStore()
    root = _base_grant(now, human_principal, agent_principal, issuer_signing_key, grant_id="root")
    mid = _base_grant(
        now,
        human_principal,
        agent_principal,
        issuer_signing_key,
        grant_id="mid",
        nonce="mid-nonce",
        expires_at=now + timedelta(minutes=45),
        parent_grant_id="root",
    )
    leaf = _base_grant(
        now,
        human_principal,
        agent_principal,
        issuer_signing_key,
        grant_id="leaf",
        nonce="leaf-nonce",
        expires_at=now + timedelta(minutes=15),
        parent_grant_id="mid",
        scope=ScopeConstraints(
            recipients=("merchant-A",),
            max_amount=MonetaryAmount(currency="INR", minor_units=1000),
        ),
    )
    verify_delegation_chain([root, mid, leaf], keyring=keyring, grant_store=store, now=now)


def test_verify_delegation_chain_rejects_empty_chain(keyring):
    from karmasakshi.errors import DelegationError
    from karmasakshi.stores.memory import InMemoryGrantStore

    with pytest.raises(DelegationError):
        verify_delegation_chain([], keyring=keyring, grant_store=InMemoryGrantStore(), now=None)


def test_verify_delegation_chain_rejects_root_with_a_parent(
    keyring, human_principal, agent_principal, issuer_signing_key, now
):
    from karmasakshi.errors import DelegationError
    from karmasakshi.stores.memory import InMemoryGrantStore

    fake_root = _base_grant(
        now,
        human_principal,
        agent_principal,
        issuer_signing_key,
        grant_id="root",
        parent_grant_id="some-other-grant",
    )
    with pytest.raises(DelegationError):
        verify_delegation_chain(
            [fake_root], keyring=keyring, grant_store=InMemoryGrantStore(), now=now
        )


def test_verify_delegation_chain_rejects_broken_parent_link(
    keyring,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    from karmasakshi.errors import DelegationError
    from karmasakshi.stores.memory import InMemoryGrantStore

    store = InMemoryGrantStore()
    root = _base_grant(now, human_principal, agent_principal, issuer_signing_key, grant_id="root")
    imposter_leaf = _base_grant(
        now,
        human_principal,
        agent_principal,
        issuer_signing_key,
        grant_id="leaf",
        nonce="leaf-nonce",
        parent_grant_id="not-actually-root",
    )
    with pytest.raises(DelegationError):
        verify_delegation_chain([root, imposter_leaf], keyring=keyring, grant_store=store, now=now)


def test_verify_delegation_chain_rejects_if_any_ancestor_revoked(
    keyring,
    human_principal,
    agent_principal,
    issuer_signing_key,
    now,
):
    from karmasakshi.stores.memory import InMemoryGrantStore

    store = InMemoryGrantStore()
    root = _base_grant(now, human_principal, agent_principal, issuer_signing_key, grant_id="root")
    leaf = _base_grant(
        now,
        human_principal,
        agent_principal,
        issuer_signing_key,
        grant_id="leaf",
        nonce="leaf-nonce",
        parent_grant_id="root",
    )
    store.revoke("root")
    with pytest.raises(GrantRevokedError):
        verify_delegation_chain([root, leaf], keyring=keyring, grant_store=store, now=now)
