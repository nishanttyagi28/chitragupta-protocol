"""FastAPI control-plane application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from karmasakshi import __version__
from karmasakshi.api.auth import is_dev_mode, is_public_demo
from karmasakshi.api.routes import router
from karmasakshi.api.state import ApiState, build_default_state
from karmasakshi.gateway.api import GatewayApiState
from karmasakshi.gateway.api import router as gateway_router
from karmasakshi.gateway.refunds import router as gateway_refunds_router
from karmasakshi.gateway.store import GatewayStore, default_gateway_db_path
from karmasakshi.tenant.control_plane import MultiTenantControlPlane


class PublicDemoMisconfiguredError(RuntimeError):
    """Raised at startup if KARMASAKSHI_PUBLIC_DEMO and KARMASAKSHI_API_DEV_MODE are both
    set. Combining them would mount the safe public demo alongside a fully unauthenticated
    copy of the real control-plane API/console -- refuse to start rather than risk that."""


def create_app(
    *,
    state: ApiState | None = None,
    data_dir: Path | None = None,
    gateway_state: GatewayApiState | None = None,
) -> FastAPI:
    if is_public_demo() and is_dev_mode():
        raise PublicDemoMisconfiguredError(
            "KARMASAKSHI_PUBLIC_DEMO=1 and KARMASAKSHI_API_DEV_MODE=1 must not both be set: "
            "the public demo is meant to be the only unauthenticated surface exposed. Unset "
            "KARMASAKSHI_API_DEV_MODE for any deployment that sets KARMASAKSHI_PUBLIC_DEMO."
        )

    public_demo = is_public_demo()
    app = FastAPI(
        title="KarmaSakshi Protocol Control Plane",
        version=__version__,
        description=(
            "Seal the intended effect. Witness the actual outcome. "
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
    from karmasakshi.protection import ResourceProtectionMiddleware, policy_from_env

    app.add_middleware(ResourceProtectionMiddleware, policy=policy_from_env())
    app.state.karmasakshi = state or build_default_state(data_dir)
    app.include_router(router)

    resolved_data_dir = data_dir or Path.cwd() / ".karmasakshi-api"
    resolved_data_dir.mkdir(parents=True, exist_ok=True)
    app.state.karmasakshi_gateway = gateway_state or GatewayApiState(
        store=GatewayStore(default_gateway_db_path(resolved_data_dir)),
        control_plane=MultiTenantControlPlane(data_root=resolved_data_dir / "tenants"),
    )
    app.include_router(gateway_router)
    app.include_router(gateway_refunds_router)

    try:
        from karmasakshi.web.console import console_router

        app.include_router(console_router)
    except ImportError:  # pragma: no cover - jinja2 is part of the `api` extra
        pass

    if public_demo:
        from karmasakshi.web.demo_router import demo_router

        app.include_router(demo_router)

    return app


__all__ = ["PublicDemoMisconfiguredError", "create_app"]
