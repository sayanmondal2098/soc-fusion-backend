"""System and admin routes for the backend API."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps.auth import require_admin_secret
from app.core import (
    BucketStorageSettings,
    FileSystemStorageSettings,
    Settings,
    get_settings,
)
from app.schemas import (
    AdminConfigStatusResponse,
    BucketStorageStatus,
    FileSystemStorageStatus,
    HealthResponse,
    StorageStatus,
)

router = APIRouter()


@router.get("/health", tags=["system"], response_model=HealthResponse)
async def health() -> HealthResponse:
    """Basic liveness response for local development and probes."""
    settings = get_settings()
    return HealthResponse(
        status="ok",
        environment=settings.environment.value,
        storage_backend=settings.storage.backend.value,
    )


@router.get(
    "/admin/config/status",
    tags=["admin"],
    dependencies=[Depends(require_admin_secret)],
    response_model=AdminConfigStatusResponse,
)
async def admin_config_status() -> AdminConfigStatusResponse:
    """Expose non-secret configuration status for protected admin checks."""
    settings = get_settings()
    return AdminConfigStatusResponse(
        service="soc-fusion-backend",
        environment=settings.environment.value,
        database_configured=bool(settings.database_url),
        otx_api_key_configured=bool(settings.otx_api_key),
        misp_url=settings.misp_url,
        misp_api_key_configured=bool(settings.misp_api_key),
        admin_auth_secret_configured=bool(settings.admin_auth_secret),
        storage=_serialize_storage(settings),
    )


def _serialize_storage(settings: Settings) -> StorageStatus:
    storage = settings.storage

    if isinstance(storage, FileSystemStorageSettings):
        return FileSystemStorageStatus(
            backend=storage.backend.value,
            raw_storage_path=str(storage.raw_storage_path),
        )

    if isinstance(storage, BucketStorageSettings):
        return BucketStorageStatus(
            backend=storage.backend.value,
            bucket_name=storage.bucket_name,
            bucket_region=storage.bucket_region,
            bucket_prefix=storage.bucket_prefix or "",
            endpoint_url=storage.endpoint_url,
        )

    raise TypeError(f"Unsupported storage settings type: {type(storage)!r}")
