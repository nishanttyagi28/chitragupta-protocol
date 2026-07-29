from __future__ import annotations

import pytest

from karmasakshi.errors import (
    CrossOrganizationAccessError,
    GatewayAdapterAlreadyExistsError,
    GatewayAdapterNotFoundError,
    GatewayAgentAlreadyExistsError,
    GatewayAgentNotFoundError,
    GatewayAuthenticationError,
    GatewayUserAlreadyExistsError,
    GatewayUserNotFoundError,
    OrganizationAlreadyExistsError,
    OrganizationNotFoundError,
    OrganizationSuspendedError,
    StoreUnavailableError,
)
from karmasakshi.gateway import GatewayStore, GatewayUserRole, OrganizationStatus
from karmasakshi.gateway.migrations import MIGRATIONS, apply_migrations


@pytest.fixture
def store(tmp_path):
    return GatewayStore(tmp_path / "gateway.db")


# --- organizations -------------------------------------------------------------


def test_create_and_get_organization(store):
    org = store.create_organization("org-1", "Acme Corp")
    assert org.org_id == "org-1"
    assert org.status == OrganizationStatus.ACTIVE
    fetched = store.get_organization("org-1")
    assert fetched == org


def test_create_duplicate_organization_fails_closed(store):
    store.create_organization("org-1", "Acme Corp")
    with pytest.raises(OrganizationAlreadyExistsError):
        store.create_organization("org-1", "Acme Corp Again")


def test_get_unknown_organization_fails_closed(store):
    with pytest.raises(OrganizationNotFoundError):
        store.get_organization("does-not-exist")


def test_list_organizations(store):
    store.create_organization("org-a", "A")
    store.create_organization("org-b", "B")
    orgs = store.list_organizations()
    assert [o.org_id for o in orgs] == ["org-a", "org-b"]


def test_suspend_and_reactivate_organization(store):
    store.create_organization("org-1", "Acme Corp")
    suspended = store.set_organization_status("org-1", OrganizationStatus.SUSPENDED)
    assert suspended.status == OrganizationStatus.SUSPENDED
    with pytest.raises(OrganizationSuspendedError):
        store.require_active_organization("org-1")
    reactivated = store.set_organization_status("org-1", OrganizationStatus.ACTIVE)
    assert reactivated.status == OrganizationStatus.ACTIVE
    store.require_active_organization("org-1")  # does not raise


def test_set_status_on_unknown_organization_fails_closed(store):
    with pytest.raises(OrganizationNotFoundError):
        store.set_organization_status("nope", OrganizationStatus.SUSPENDED)


# --- users --------------------------------------------------------------------


def test_create_user_requires_active_organization(store):
    with pytest.raises(OrganizationNotFoundError):
        store.create_user(
            user_id="u1", org_id="no-such-org", email="a@b.com", display_name="A", password="x"
        )


def test_create_user_fails_when_organization_suspended(store):
    store.create_organization("org-1", "Acme Corp")
    store.set_organization_status("org-1", OrganizationStatus.SUSPENDED)
    with pytest.raises(OrganizationSuspendedError):
        store.create_user(
            user_id="u1", org_id="org-1", email="a@b.com", display_name="A", password="x"
        )


def test_create_and_get_user(store):
    store.create_organization("org-1", "Acme Corp")
    user = store.create_user(
        user_id="u1",
        org_id="org-1",
        email="alice@acme.com",
        display_name="Alice",
        password="hunter2",
        role=GatewayUserRole.OWNER,
    )
    assert user.role == GatewayUserRole.OWNER
    fetched = store.get_user("org-1", "alice@acme.com")
    assert fetched == user


def test_create_duplicate_user_in_same_org_fails_closed(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_user(
        user_id="u1", org_id="org-1", email="alice@acme.com", display_name="Alice", password="x"
    )
    with pytest.raises(GatewayUserAlreadyExistsError):
        store.create_user(
            user_id="u2",
            org_id="org-1",
            email="alice@acme.com",
            display_name="Alice2",
            password="y",
        )


def test_same_email_allowed_in_different_organizations(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_organization("org-2", "Beta Corp")
    u1 = store.create_user(
        user_id="u1", org_id="org-1", email="alice@example.com", display_name="Alice", password="x"
    )
    u2 = store.create_user(
        user_id="u2", org_id="org-2", email="alice@example.com", display_name="Alice", password="y"
    )
    assert u1.user_id != u2.user_id
    assert u1.org_id != u2.org_id


def test_get_unknown_user_fails_closed(store):
    store.create_organization("org-1", "Acme Corp")
    with pytest.raises(GatewayUserNotFoundError):
        store.get_user("org-1", "nobody@acme.com")


def test_list_users_scoped_to_organization(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_organization("org-2", "Beta Corp")
    store.create_user(
        user_id="u1", org_id="org-1", email="a@acme.com", display_name="A", password="x"
    )
    store.create_user(
        user_id="u2", org_id="org-2", email="b@beta.com", display_name="B", password="y"
    )
    org1_users = store.list_users("org-1")
    assert [u.email for u in org1_users] == ["a@acme.com"]


# --- authentication -------------------------------------------------------------


def test_authenticate_succeeds_with_correct_credentials(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_user(
        user_id="u1",
        org_id="org-1",
        email="alice@acme.com",
        display_name="Alice",
        password="hunter2",
    )
    user = store.authenticate(org_id="org-1", email="alice@acme.com", password="hunter2")
    assert user.user_id == "u1"


def test_authenticate_rejects_wrong_password(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_user(
        user_id="u1",
        org_id="org-1",
        email="alice@acme.com",
        display_name="Alice",
        password="hunter2",
    )
    with pytest.raises(GatewayAuthenticationError):
        store.authenticate(org_id="org-1", email="alice@acme.com", password="wrong")


def test_authenticate_rejects_unknown_email(store):
    store.create_organization("org-1", "Acme Corp")
    with pytest.raises(GatewayAuthenticationError):
        store.authenticate(org_id="org-1", email="nobody@acme.com", password="whatever")


def test_authenticate_rejects_unknown_organization(store):
    with pytest.raises(GatewayAuthenticationError):
        store.authenticate(org_id="no-such-org", email="a@b.com", password="whatever")


def test_authenticate_rejects_suspended_organization(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_user(
        user_id="u1",
        org_id="org-1",
        email="alice@acme.com",
        display_name="Alice",
        password="hunter2",
    )
    store.set_organization_status("org-1", OrganizationStatus.SUSPENDED)
    with pytest.raises(GatewayAuthenticationError):
        store.authenticate(org_id="org-1", email="alice@acme.com", password="hunter2")


def test_authenticate_correct_password_wrong_organization_fails_closed(store):
    """A user of org-1 cannot authenticate against org-2 even with the
    right email+password, because email is scoped per-org -- exercises
    cross-tenant rejection at the authentication boundary."""
    store.create_organization("org-1", "Acme Corp")
    store.create_organization("org-2", "Beta Corp")
    store.create_user(
        user_id="u1",
        org_id="org-1",
        email="alice@acme.com",
        display_name="Alice",
        password="hunter2",
    )
    with pytest.raises(GatewayAuthenticationError):
        store.authenticate(org_id="org-2", email="alice@acme.com", password="hunter2")


def test_assert_user_belongs_to_organization_passes_for_matching_org(store):
    store.create_organization("org-1", "Acme Corp")
    user = store.create_user(
        user_id="u1", org_id="org-1", email="alice@acme.com", display_name="Alice", password="x"
    )
    store.assert_user_belongs_to_organization(user, "org-1")  # does not raise


def test_assert_user_belongs_to_organization_rejects_cross_org(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_organization("org-2", "Beta Corp")
    user = store.create_user(
        user_id="u1", org_id="org-1", email="alice@acme.com", display_name="Alice", password="x"
    )
    with pytest.raises(CrossOrganizationAccessError):
        store.assert_user_belongs_to_organization(user, "org-2")


# --- evaluation resource inventory --------------------------------------------


def test_agent_registration_is_idempotent_and_organization_scoped(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_organization("org-2", "Beta Corp")

    first = store.register_agent(
        org_id="org-1", agent_id="refund-agent", display_name="Refund Agent"
    )
    repeated = store.register_agent(
        org_id="org-1", agent_id="refund-agent", display_name="Refund Agent"
    )
    other = store.register_agent(
        org_id="org-2", agent_id="refund-agent", display_name="Beta Refund Agent"
    )

    assert repeated == first
    assert store.get_agent("org-1", "refund-agent") == first
    assert store.list_agents("org-1") == [first]
    assert other.org_id == "org-2"
    assert other.display_name == "Beta Refund Agent"


def test_agent_registration_rejects_changed_identity_and_unknown_lookup(store):
    store.create_organization("org-1", "Acme Corp")
    store.register_agent(org_id="org-1", agent_id="refund-agent", display_name="Refund Agent")

    with pytest.raises(GatewayAgentAlreadyExistsError):
        store.register_agent(
            org_id="org-1",
            agent_id="refund-agent",
            display_name="Changed Agent",
        )
    with pytest.raises(GatewayAgentNotFoundError):
        store.get_agent("org-1", "missing-agent")


def test_adapter_registration_is_idempotent_and_organization_scoped(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_organization("org-2", "Beta Corp")

    first = store.register_adapter(
        org_id="org-1",
        adapter_id="payment.simulator",
        adapter_version="1.0.0",
        effect_types=("payment.transfer",),
    )
    repeated = store.register_adapter(
        org_id="org-1",
        adapter_id="payment.simulator",
        adapter_version="1.0.0",
        effect_types=("payment.transfer",),
    )
    other = store.register_adapter(
        org_id="org-2",
        adapter_id="payment.simulator",
        adapter_version="1.0.0",
        effect_types=("payment.transfer",),
    )

    assert repeated == first
    assert store.get_adapter("org-1", "payment.simulator") == first
    assert store.list_adapters("org-1") == [first]
    assert other.org_id == "org-2"


def test_adapter_registration_rejects_changed_version_and_unknown_lookup(store):
    store.create_organization("org-1", "Acme Corp")
    store.register_adapter(
        org_id="org-1",
        adapter_id="payment.simulator",
        adapter_version="1.0.0",
        effect_types=("payment.transfer",),
    )

    with pytest.raises(GatewayAdapterAlreadyExistsError):
        store.register_adapter(
            org_id="org-1",
            adapter_id="payment.simulator",
            adapter_version="2.0.0",
            effect_types=("payment.transfer",),
        )
    with pytest.raises(GatewayAdapterNotFoundError):
        store.get_adapter("org-1", "missing-adapter")


def test_password_hash_never_equals_plaintext(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_user(
        user_id="u1",
        org_id="org-1",
        email="alice@acme.com",
        display_name="Alice",
        password="hunter2",
    )
    row = store._conn.execute(
        "SELECT password_hash, password_salt FROM gateway_users WHERE user_id = ?", ("u1",)
    ).fetchone()
    assert "hunter2" not in row["password_hash"]
    assert row["password_hash"] != "hunter2"
    assert len(row["password_salt"]) > 0


# --- store-unavailable fail-closed behavior -------------------------------------


def test_store_unavailable_on_create_organization_fails_closed(store):
    store._conn.close()
    with pytest.raises(StoreUnavailableError):
        store.create_organization("org-1", "Acme Corp")


def test_store_unavailable_on_get_organization_fails_closed(store):
    store.create_organization("org-1", "Acme Corp")
    store._conn.close()
    with pytest.raises(StoreUnavailableError):
        store.get_organization("org-1")


def test_store_unavailable_on_list_organizations_fails_closed(store):
    store._conn.close()
    with pytest.raises(StoreUnavailableError):
        store.list_organizations()


def test_store_unavailable_on_set_organization_status_fails_closed(store):
    store.create_organization("org-1", "Acme Corp")
    store._conn.close()
    with pytest.raises(StoreUnavailableError):
        store.set_organization_status("org-1", OrganizationStatus.SUSPENDED)


def test_store_unavailable_on_create_user_fails_closed(store):
    store.create_organization("org-1", "Acme Corp")
    store._conn.close()
    with pytest.raises(StoreUnavailableError):
        store.create_user(
            user_id="u1", org_id="org-1", email="a@b.com", display_name="A", password="x"
        )


def test_store_unavailable_on_get_user_fails_closed(store):
    store.create_organization("org-1", "Acme Corp")
    store._conn.close()
    with pytest.raises(StoreUnavailableError):
        store.get_user("org-1", "a@b.com")


def test_store_unavailable_on_list_users_fails_closed(store):
    store.create_organization("org-1", "Acme Corp")
    store._conn.close()
    with pytest.raises(StoreUnavailableError):
        store.list_users("org-1")


def test_store_unavailable_on_authenticate_fails_closed(store):
    store.create_organization("org-1", "Acme Corp")
    store.create_user(user_id="u1", org_id="org-1", email="a@b.com", display_name="A", password="x")
    store._conn.close()
    with pytest.raises(StoreUnavailableError):
        store.authenticate(org_id="org-1", email="a@b.com", password="x")


# --- migrations -----------------------------------------------------------------


def test_migrations_applied_on_construction(tmp_path):
    import sqlite3

    GatewayStore(tmp_path / "gateway.db")
    conn = sqlite3.connect(tmp_path / "gateway.db")
    applied = {row[0] for row in conn.execute("SELECT id FROM schema_migrations")}
    assert applied == {m.id for m in MIGRATIONS}
    conn.close()


def test_migrations_are_idempotent(tmp_path):
    import sqlite3

    path = tmp_path / "gateway.db"
    GatewayStore(path)  # applies migrations once
    conn = sqlite3.connect(path)
    newly_applied = apply_migrations(conn)
    assert newly_applied == []  # nothing left to apply
    conn.close()


def test_reopening_store_does_not_reapply_migrations(tmp_path):
    path = tmp_path / "gateway.db"
    store1 = GatewayStore(path)
    store1.create_organization("org-1", "Acme Corp")
    store1.close()

    store2 = GatewayStore(path)
    org = store2.get_organization("org-1")
    assert org.name == "Acme Corp"
