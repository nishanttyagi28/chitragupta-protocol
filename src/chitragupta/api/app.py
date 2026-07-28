"""FastAPI control-plane application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from chitragupta import __version__
from chitragupta.api.auth import is_dev_mode, is_public_demo
from chitragupta.api.routes import router
from chitragupta.api.state import ApiState, build_default_state


class PublicDemoMisconfiguredError(RuntimeError):
    """Raised at startup if CHITRAGUPTA_PUBLIC_DEMO and CHITRAGUPTA_API_DEV_MODE are both
    set. Combining them would mount the safe public demo alongside a fully unauthenticated
    copy of the real control-plane API/console -- refuse to start rather than risk that."""


def create_app(*, state: ApiState | None = None, data_dir: Path | None = None) -> FastAPI:
    if is_public_demo() and is_dev_mode():
        raise PublicDemoMisconfiguredError(
            "CHITRAGUPTA_PUBLIC_DEMO=1 and CHITRAGUPTA_API_DEV_MODE=1 must not both be set: "
            "the public demo is meant to be the only unauthenticated surface exposed. Unset "
            "CHITRAGUPTA_API_DEV_MODE for any deployment that sets CHITRAGUPTA_PUBLIC_DEMO."
        )

    public_demo = is_public_demo()
    app = FastAPI(
        title="Chitragupta Protocol Control Plane",
        version=__version__,
        description=(
            "Seal the intended effect. Verify the actual outcome. "
            + ("**Running in unauthenticated local development mode.**" if is_dev_mode() else "")
            + ("**Public sandbox demo mode: see /demo/**" if public_demo else "")
        ),
        # No interactive API docs in public-demo deployments: the documented surface there
        # is /demo/*, not the authenticated control-plane API, and admin/kill-switch routes
        # should not be advertised to unauthenticated visitors.
        docs_url=None if public_demo else "/docs",
        redoc_url=None if public_demo else "/redoc",
        openapi_url=None if public_demo else "/openapi.json",
    )
    app.state.chitragupta = state or build_default_state(data_dir)
    app.include_router(router)

    try:
        from chitragupta.web.console import console_router

        app.include_router(console_router)
    except ImportError:  # pragma: no cover - jinja2 is part of the `api` extra
        pass

    if public_demo:
        from chitragupta.web.demo_router import demo_router

        app.include_router(demo_router)

    return app


__all__ = ["PublicDemoMisconfiguredError", "create_app"]
