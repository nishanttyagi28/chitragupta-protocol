"""Multi-party (M-of-N) authorization (extreme-v2 Phase 3).

See docs/multi-party-authorization.md.
"""

from __future__ import annotations

from karmasakshi.approval.model import ApprovalStatement, Decision, QuorumResult
from karmasakshi.approval.policy import (
    DEFAULT_APPROVAL_POLICY,
    POLICY_TYPE_APPROVAL,
    ApprovalPolicy,
    approval_policy_from_bundle_payload,
    build_approval_policy_bundle,
)
from karmasakshi.approval.quorum import evaluate_quorum
from karmasakshi.approval.signing import (
    sign_approval_statement,
    verify_approval_statement,
    verify_approval_statement_signature,
    verify_approval_statement_time_window,
)

__all__ = [
    "DEFAULT_APPROVAL_POLICY",
    "POLICY_TYPE_APPROVAL",
    "ApprovalPolicy",
    "ApprovalStatement",
    "Decision",
    "QuorumResult",
    "approval_policy_from_bundle_payload",
    "build_approval_policy_bundle",
    "evaluate_quorum",
    "sign_approval_statement",
    "verify_approval_statement",
    "verify_approval_statement_signature",
    "verify_approval_statement_time_window",
]
