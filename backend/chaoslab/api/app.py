"""FastAPI app factory wiring routers, DB session factory, CORS, and security headers."""

from __future__ import annotations

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

import chaoslab.db.registry  # noqa: F401
from chaoslab import __version__
from chaoslab.api.routers import (
    admin,
    audit,
    auth,
    environments,
    health,
    imports,
    reports,
    scenarios,
    snapshots,
)
from chaoslab.config import Settings, get_settings
from chaoslab.db.session import create_db_engine, make_session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()
    engine = create_db_engine(cfg.database_url)
    session_factory = make_session_factory(engine)

    app = FastAPI(
        title="CHAOS LAB API",
        version=__version__,
        description="Offline attack-path modeling and scenario simulator.",
    )
    app.state.settings = cfg
    app.state.engine = engine
    app.state.session_factory = session_factory

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Requested-With"],
    )

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next) -> Response:
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        return response

    app.include_router(health.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(environments.router, prefix="/api")
    app.include_router(imports.router, prefix="/api")
    app.include_router(snapshots.router, prefix="/api")
    app.include_router(scenarios.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")
    app.include_router(audit.router, prefix="/api")
    app.include_router(admin.router, prefix="/api")

    return app


def get_asgi_app() -> FastAPI:
    """Lazy ASGI app factory for uvicorn --factory chaoslab.api.app:get_asgi_app."""
    return create_app()
