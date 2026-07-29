"""Deep ancestor revocation checks (extreme-v2 Phase 11)."""

from __future__ import annotations

from karmasakshi.errors import DelegationLineageError, GrantRevokedError
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.stores.base import GrantStore

#: Hard ceiling on ancestor walk depth (resource protection / cycle guard).
MAX_DELEGATION_DEPTH = 16


def assert_no_revoked_ancestors(
    grant: ExecutionGrant,
    grant_store: GrantStore,
    *,
    max_depth: int = MAX_DELEGATION_DEPTH,
) -> tuple[str, ...]:
    """Walk the grant's ancestor lineage via the store and fail closed if any
    ancestor is revoked.

    Uses ``grant.parent_grant_id`` for the first hop, then
    ``grant_store.get_parent_grant_id`` for deeper hops (Phase 11 lineage
    map). Returns the ordered tuple of ancestor grant ids that were
    checked (empty for a root grant).

    Fail-closed rules:
    - Any revoked ancestor raises ``GrantRevokedError``.
    - Missing lineage for an intermediate grant that should have a parent
      recorded raises ``DelegationLineageError`` (revocation uncertainty).
    - Cycles or depth > ``max_depth`` raise ``DelegationLineageError``.
    """
    if max_depth < 1 or max_depth > MAX_DELEGATION_DEPTH:
        raise DelegationLineageError(f"max_depth must be 1-{MAX_DELEGATION_DEPTH}, got {max_depth}")

    parent_id = grant.parent_grant_id
    if parent_id is None:
        return ()

    checked: list[str] = []
    seen: set[str] = {grant.grant_id}
    current: str | None = parent_id
    depth = 0
    while current is not None:
        depth += 1
        if depth > max_depth:
            raise DelegationLineageError(
                f"delegation ancestor walk exceeded max_depth={max_depth} "
                f"for grant {grant.grant_id}"
            )
        if current in seen:
            raise DelegationLineageError(
                f"cycle detected in delegation lineage at grant {current} (from {grant.grant_id})"
            )
        seen.add(current)
        if grant_store.is_revoked(current):
            raise GrantRevokedError(
                f"grant {grant.grant_id} blocked: ancestor grant {current} is revoked "
                f"(depth={depth})"
            )
        checked.append(current)
        next_parent = grant_store.get_parent_grant_id(current)
        # Distinguish "root" (lineage recorded as None) from "unknown"
        # (no lineage row). Unknown intermediate lineage is fail-closed.
        if next_parent is None and not grant_store.has_lineage(current):
            raise DelegationLineageError(
                f"lineage unknown for ancestor grant {current}; "
                f"cannot prove deep revocation safety for {grant.grant_id}"
            )
        current = next_parent
    return tuple(checked)


__all__ = ["MAX_DELEGATION_DEPTH", "assert_no_revoked_ancestors"]
