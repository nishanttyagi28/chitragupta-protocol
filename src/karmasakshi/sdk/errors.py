"""SDK-specific errors (Milestone A).

Deliberately separate from `karmasakshi.errors.KarmaSakshiError`: the SDK
is an HTTP client for a remote Gateway, and a non-2xx response is a
transport-and-application-level fact about that remote call, not a
protocol-engine security decision made in this process.
"""

from __future__ import annotations


class KarmaSakshiSdkError(Exception):
    """Base class for all SDK errors."""


class KarmaSakshiApiError(KarmaSakshiSdkError):
    """The Gateway responded with a non-2xx status code."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Gateway API error {status_code}: {detail}")


class KarmaSakshiConnectionError(KarmaSakshiSdkError):
    """Could not reach the Gateway at all (DNS, connection refused, TLS,
    timeout before any response was received)."""


__all__ = ["KarmaSakshiApiError", "KarmaSakshiConnectionError", "KarmaSakshiSdkError"]
