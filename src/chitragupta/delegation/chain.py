"""Delegation chain verification.

A leaf grant used to authorize a commit may be several delegation hops
removed from the root (human/service) authorization. Every hop must
independently verify (signature, time window, not revoked) *and* be
narrower-or-equal to its immediate parent -- a chain is only as trustworthy
as its weakest link (invariants #15-#18).
"""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta

from chitragupta.crypto.keyring import Keyring
from chitragupta.delegation.attenuation import assert_grant_narrower_or_equal
from chitragupta.errors import DelegationError, GrantRevokedError
from chitragupta.grants.model import ExecutionGrant
from chitragupta.grants.verifier import verify_grant
from chitragupta.stores.base import GrantStore


def verify_delegation_chain(
    chain: list[ExecutionGrant],
    *,
    keyring: Keyring,
    grant_store: GrantStore,
    now: datetime,
    leeway: timedelta = timedelta(seconds=0),
) -> None:
    """Verify a delegation chain from root (``chain[0]``) to leaf
    (``chain[-1]``). Raises on the first problem found; never returns a
    partial "mostly valid" verdict.
    """
    if not chain:
        raise DelegationError("delegation chain must contain at least one grant")

    root = chain[0]
    if root.parent_grant_id is not None:
        raise DelegationError(
            f"chain root {root.grant_id} declares parent_grant_id={root.parent_grant_id!r}; "
            f"a verified chain must start at a true root"
        )

    for grant in chain:
        verify_grant(grant, keyring, now=now, leeway=leeway)
        if grant_store.is_revoked(grant.grant_id):
            raise GrantRevokedError(f"grant {grant.grant_id} in delegation chain is revoked")

    for parent, child in itertools.pairwise(chain):
        if child.parent_grant_id != parent.grant_id:
            raise DelegationError(
                f"grant {child.grant_id} declares parent_grant_id={child.parent_grant_id!r}, "
                f"expected {parent.grant_id!r}"
            )
        assert_grant_narrower_or_equal(child, parent)


__all__ = ["verify_delegation_chain"]
