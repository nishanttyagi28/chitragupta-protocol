from __future__ import annotations

from chitragupta.delegation.attenuation import (
    assert_grant_narrower_or_equal,
    assert_scope_narrower_or_equal,
)
from chitragupta.delegation.chain import verify_delegation_chain

__all__ = [
    "assert_grant_narrower_or_equal",
    "assert_scope_narrower_or_equal",
    "verify_delegation_chain",
]
