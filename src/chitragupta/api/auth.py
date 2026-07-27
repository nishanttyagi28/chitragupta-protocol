"""Authentication for the control-plane API.

Unauthenticated access is only permitted when ``CHITRAGUPTA_API_DEV_MODE=1``
is explicitly set -- and every response in that mode is labeled as such.
Any other configuration requires a bearer token matching
``CHITRAGUPTA_API_TOKEN``; if that variable is unset outside dev mode, the
server refuses to serve authenticated routes at all (fail closed) rather
than silently falling back to no authentication.
"""

from __future__ import annotations

import os

from fastapi import Header, HTTPException

DEV_MODE_ENV = "CHITRAGUPTA_API_DEV_MODE"
TOKEN_ENV = "CHITRAGUPTA_API_TOKEN"  # noqa: S105  # nosec B105 - env var *name*, not a credential


def is_dev_mode() -> bool:
    return os.environ.get(DEV_MODE_ENV) == "1"


async def require_auth(authorization: str | None = Header(default=None)) -> None:
    if is_dev_mode():
        return
    token = os.environ.get(TOKEN_ENV)
    if not token:
        raise HTTPException(
            status_code=500,
            detail=(
                f"{TOKEN_ENV} is not configured; refusing to serve authenticated routes "
                f"unauthenticated. Set {DEV_MODE_ENV}=1 only for local development."
            ),
        )
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="unauthorized")


__all__ = ["DEV_MODE_ENV", "TOKEN_ENV", "is_dev_mode", "require_auth"]
