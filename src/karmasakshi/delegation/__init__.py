from __future__ import annotations

from karmasakshi.delegation.attenuation import (
    assert_grant_narrower_or_equal,
    assert_scope_narrower_or_equal,
)
from karmasakshi.delegation.chain import verify_delegation_chain
from karmasakshi.delegation.revocation import (
    MAX_DELEGATION_DEPTH,
    assert_no_revoked_ancestors,
)

__all__ = [
    "MAX_DELEGATION_DEPTH",
    "assert_grant_narrower_or_equal",
    "assert_no_revoked_ancestors",
    "assert_scope_narrower_or_equal",
    "verify_delegation_chain",
]
