"""Shared Pydantic request and response models for backend API endpoints."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class APIModel(BaseModel):
    """Base Pydantic model for API contracts."""

    model_config = ConfigDict(extra="forbid")


class RootStatusResponse(APIModel):
    service: str
    status: str
    environment: str


class HealthResponse(APIModel):
    status: str
    environment: str
    storage_backend: str


class FileSystemStorageStatus(APIModel):
    backend: str
    raw_storage_path: str


class BucketStorageStatus(APIModel):
    backend: str
    bucket_name: str
    bucket_region: str | None = None
    bucket_prefix: str = ""
    endpoint_url: str | None = None


StorageStatus = FileSystemStorageStatus | BucketStorageStatus


class AdminConfigStatusResponse(APIModel):
    service: str
    environment: str
    database_configured: bool
    otx_api_key_configured: bool
    misp_url: str
    misp_api_key_configured: bool
    admin_auth_secret_configured: bool
    storage: StorageStatus
