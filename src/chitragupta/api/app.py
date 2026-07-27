"""FastAPI control-plane application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from chitragupta import __version__
from chitragupta.api.auth import is_dev_mode
from chitragupta.api.routes import router
from chitragupta.api.state import ApiState, build_default_state


def create_app(*, state: ApiState | None = None, data_dir: Path | None = None) -> FastAPI:
    app = FastAPI(
        title="Chitragupta Protocol Control Plane",
        version=__version__,
        description=(
            "Seal the intended effect. Verify the actual outcome. "
            + ("**Running in unauthenticated local development mode.**" if is_dev_mode() else "")
        ),
    )
    app.state.chitragupta = state or build_default_state(data_dir)
    app.include_router(router)

    try:
        from chitragupta.web.console import console_router

        app.include_router(console_router)
    except ImportError:  # pragma: no cover - jinja2 is part of the `api` extra
        pass

    return app


__all__ = ["create_app"]
