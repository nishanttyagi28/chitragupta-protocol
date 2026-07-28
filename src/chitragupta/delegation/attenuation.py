"""Deterministic constraint comparison for delegation attenuation.

A child grant may only ever narrow (or exactly match) its parent along
every dimension: resources, recipients, amount, fields, effect types,
audience, time window, and use count (invariants #15-#18). Constraints
that cannot be safely compared (e.g. amounts in different currencies) are
never treated as "probably fine" -- they raise
:class:`~chitragupta.errors.IncomparableConstraintError`, which callers
must treat as a widening attempt (fail closed).
"""

from __future__ import annotations

from chitragupta.domain.common import MonetaryAmount
from chitragupta.errors import ConstraintWideningError, IncomparableConstraintError
from chitragupta.grants.model import ExecutionGrant, ScopeConstraints


def _assert_allow_list_narrower_or_equal(
    child: tuple[str, ...] | None, parent: tuple[str, ...] | None, dimension: str
) -> None:
    if parent is None:
        return  # parent is unrestricted on this dimension; any child value is allowed
    if child is None:
        raise ConstraintWideningError(
            f"{dimension}: child is unrestricted (null) but parent restricts to {sorted(parent)}"
        )
    child_set, parent_set = set(child), set(parent)
    if not child_set.issubset(parent_set):
        extra = sorted(child_set - parent_set)
        raise ConstraintWideningError(
            f"{dimension}: child allows {extra} which parent does not permit "
            f"(parent allows {sorted(parent_set)})"
        )


def _assert_amount_narrower_or_equal(
    child: MonetaryAmount | None, parent: MonetaryAmount | None
) -> None:
    if parent is None:
        return
    if child is None:
        raise ConstraintWideningError(
            f"max_amount: child is unrestricted (null) but parent caps at {parent}"
        )
    if child.currency != parent.currency:
        raise IncomparableConstraintError(
            f"max_amount: cannot compare {child.currency} (child) with "
            f"{parent.currency} (parent); treated as widening"
        )
    if child.minor_units > parent.minor_units:
        raise ConstraintWideningError(f"max_amount: child cap {child} exceeds parent cap {parent}")


def assert_scope_narrower_or_equal(child: ScopeConstraints, parent: ScopeConstraints) -> None:
    """Raise if ``child`` is not narrower-than-or-equal-to ``parent`` on every
    dimension. Never returns a truthy/falsy verdict silently -- every failure
    is a specific, actionable exception."""
    _assert_allow_list_narrower_or_equal(
        child.target_resources, parent.target_resources, "target_resources"
    )
    _assert_allow_list_narrower_or_equal(child.recipients, parent.recipients, "recipients")
    _assert_amount_narrower_or_equal(child.max_amount, parent.max_amount)
    _assert_allow_list_narrower_or_equal(
        child.allowed_fields, parent.allowed_fields, "allowed_fields"
    )
    _assert_allow_list_narrower_or_equal(child.environments, parent.environments, "environments")


def assert_grant_narrower_or_equal(child: ExecutionGrant, parent: ExecutionGrant) -> None:
    """Full attenuation check between a proposed child grant and its parent.

    Covers scope, audience, allowed effect types, the time window, and
    max_uses (invariants #16-#18).
    """
    if child.expires_at > parent.expires_at:
        raise ConstraintWideningError(
            f"expires_at: child ({child.expires_at.isoformat()}) outlives parent "
            f"({parent.expires_at.isoformat()})"
        )
    if child.not_before < parent.not_before:
        raise ConstraintWideningError(
            f"not_before: child ({child.not_before.isoformat()}) starts before parent "
            f"({parent.not_before.isoformat()})"
        )
    if child.max_uses > parent.max_uses:
        raise ConstraintWideningError(
            f"max_uses: child ({child.max_uses}) exceeds parent ({parent.max_uses})"
        )
    _assert_allow_list_narrower_or_equal(child.audience, parent.audience, "audience")
    _assert_allow_list_narrower_or_equal(
        child.allowed_effect_types, parent.allowed_effect_types, "allowed_effect_types"
    )
    assert_scope_narrower_or_equal(child.scope, parent.scope)


__all__ = ["assert_grant_narrower_or_equal", "assert_scope_narrower_or_equal"]
