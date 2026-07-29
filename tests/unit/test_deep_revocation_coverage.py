"""Coverage for deep revocation edge cases."""

from datetime import timedelta

import pytest

from karmasakshi.delegation.revocation import MAX_DELEGATION_DEPTH, assert_no_revoked_ancestors
from karmasakshi.errors import DelegationLineageError
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.stores.memory import InMemoryGrantStore
from karmasakshi.stores.sqlite import SQLiteGrantStore


def test_max_depth_and_cycle(now, issuer_signing_key, human_principal, tmp_path):
    from karmasakshi.grants.issuer import issue_grant

    store = InMemoryGrantStore()
    mh = "sha256:" + "9" * 64
    a = issue_grant(
        grant_id="a",
        issuer=human_principal,
        subject=human_principal,
        audience=("x",),
        allowed_effect_types=("e",),
        scope=ScopeConstraints(),
        not_before=now,
        expires_at=now + timedelta(hours=1),
        nonce="n1",
        signing_key=issuer_signing_key,
        manifest_hash=mh,
        parent_grant_id="b",
    )
    store.record_lineage("a", "b")
    store.record_lineage("b", "a")  # cycle
    with pytest.raises(DelegationLineageError, match="cycle"):
        assert_no_revoked_ancestors(a, store)

    with pytest.raises(DelegationLineageError, match="max_depth"):
        assert_no_revoked_ancestors(a, store, max_depth=99)


def test_sqlite_lineage_round_trip(tmp_path):
    store = SQLiteGrantStore(tmp_path / "g.db")
    store.record_lineage("root", None)
    store.record_lineage("child", "root")
    assert store.has_lineage("root")
    assert store.get_parent_grant_id("root") is None
    assert store.get_parent_grant_id("child") == "root"
    assert not store.has_lineage("missing")
    assert MAX_DELEGATION_DEPTH == 16
    store.close()
