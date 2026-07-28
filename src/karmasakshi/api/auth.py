"""Authentication for the control-plane API.

Unauthenticated access is only permitted when ``KARMASAKSHI_API_DEV_MODE=1``
is explicitly set -- and every response in that mode is labeled as such.
Any other configuration requires a bearer token matching
``KARMASAKSHI_API_TOKEN``; if that variable is unset outside dev mode, the
server refuses to serve authenticated routes at all (fail closed) rather
than silently falling back to no authentication.
"""

from __future__ import annotations

import os

from fastapi import Header, HTTPException

DEV_MODE_ENV = "KARMASAKSHI_API_DEV_MODE"
TOKEN_ENV = "KARMASAKSHI_API_TOKEN"  # noqa: S105  # nosec B105 - env var *name*, not a credential
PUBLIC_DEMO_ENV = "KARMASAKSHI_PUBLIC_DEMO"


def is_dev_mode() -> bool:
    return os.environ.get(DEV_MODE_ENV) == "1"


def is_public_demo() -> bool:
    """Whether the safe, unauthenticated public demo surface (``/demo/*``) is
    mounted. Independent of ``is_dev_mode()``: the public demo never grants
    access to the real control-plane API or console -- those stay fail-closed
    exactly as they do in any other non-dev deployment (see docs/deployment.md).
    """
    return os.environ.get(PUBLIC_DEMO_ENV) == "1"


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


__all__ = [
    "DEV_MODE_ENV",
    "PUBLIC_DEMO_ENV",
    "TOKEN_ENV",
    "is_dev_mode",
    "is_public_demo",
    "require_auth",
]
