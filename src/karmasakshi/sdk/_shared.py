"""Shared, I/O-free helpers for the sync and async Gateway SDK clients.

Not part of the public SDK surface -- imported by `karmasakshi.sdk.client`
and `karmasakshi.sdk.async_client` only.
"""

from __future__ import annotations

import httpx

from karmasakshi.sdk.errors import KarmaSakshiApiError

DEFAULT_BLOCK_THRESHOLD = 80
DEFAULT_REVIEW_THRESHOLD = 50
DEFAULT_POLICY_EFFECTIVE_SECONDS = 365 * 24 * 3600
DEFAULT_GRANT_TTL_SECONDS = 300
DEFAULT_SOURCE_ACCOUNT = "acct-src"
DEFAULT_CURRENCY = "INR"


def raise_for_status(response: httpx.Response) -> None:
    """Translate a non-2xx Gateway response into `KarmaSakshiApiError`,
    extracting FastAPI's conventional ``{"detail": "..."}`` body when
    present rather than surfacing raw response text."""
    if response.status_code < 400:
        return
    detail = response.text
    try:
        body = response.json()
        if isinstance(body, dict) and "detail" in body:
            detail = str(body["detail"])
    except ValueError:
        pass
    raise KarmaSakshiApiError(response.status_code, detail)


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


__all__ = [
    "DEFAULT_BLOCK_THRESHOLD",
    "DEFAULT_CURRENCY",
    "DEFAULT_GRANT_TTL_SECONDS",
    "DEFAULT_POLICY_EFFECTIVE_SECONDS",
    "DEFAULT_REVIEW_THRESHOLD",
    "DEFAULT_SOURCE_ACCOUNT",
    "auth_header",
    "raise_for_status",
]
