"""ASGI entrypoint for the soc-fusion backend API."""

from __future__ import annotations

from fastapi import FastAPI

from app.api.middleware import CorrelationIdMiddleware
from app.api.routes.system import router as system_router
from app.core import configure_logging, get_logger, log_api_event, validate_startup_settings
from app.schemas import RootStatusResponse


def create_app() -> FastAPI:
    """Create the API application and fail fast on invalid configuration."""
    settings = validate_startup_settings()
    configure_logging(debug=settings.debug)
    logger = get_logger("soc_fusion.api.application")

    app = FastAPI(
        title="soc-fusion-backend",
        version="0.1.0",
        summary="Backend API for SoC Fusion.",
    )
    app.state.settings = settings
    app.add_middleware(CorrelationIdMiddleware)
    app.include_router(system_router)

    log_api_event(
        logger,
        "application.started",
        environment=settings.environment.value,
    )

    @app.get("/", tags=["system"], response_model=RootStatusResponse)
    async def root() -> RootStatusResponse:
        return RootStatusResponse(
            service="soc-fusion-backend",
            status="ready",
            environment=settings.environment.value,
        )

    return app


app = create_app()
