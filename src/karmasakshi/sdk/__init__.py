"""Typed synchronous and asynchronous Python SDK for the KarmaSakshi
Gateway HTTP API (commercial Milestone A). Optional -- requires the
``sdk`` extra (``pip install karmasakshi-protocol[sdk]``, adds
``httpx``). See docs/gateway.md and docs/sdk.md.
"""

from __future__ import annotations

from karmasakshi.gateway.refund_schemas import (
    RefundDenyResult,
    RefundDetailOut,
    RefundEffectView,
    RefundPolicyDecisionOut,
    RefundSummaryOut,
)
from karmasakshi.sdk.async_client import AsyncGatewayClient
from karmasakshi.sdk.client import GatewayClient
from karmasakshi.sdk.errors import (
    KarmaSakshiApiError,
    KarmaSakshiConnectionError,
    KarmaSakshiSdkError,
)
from karmasakshi.sdk.models import (
    ApprovalResult,
    AuditVerificationResult,
    CompensationResult,
    ExecutionResult,
    PolicyActivationResult,
    RefundAssessment,
    RefundProposalResult,
    SimulatorInjectionResult,
    VerificationResult,
)

__all__ = [
    "ApprovalResult",
    "AsyncGatewayClient",
    "AuditVerificationResult",
    "CompensationResult",
    "ExecutionResult",
    "GatewayClient",
    "KarmaSakshiApiError",
    "KarmaSakshiConnectionError",
    "KarmaSakshiSdkError",
    "PolicyActivationResult",
    "RefundAssessment",
    "RefundDenyResult",
    "RefundDetailOut",
    "RefundEffectView",
    "RefundPolicyDecisionOut",
    "RefundProposalResult",
    "RefundSummaryOut",
    "SimulatorInjectionResult",
    "VerificationResult",
]
