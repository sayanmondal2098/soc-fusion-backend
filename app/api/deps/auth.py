"""Authentication helpers for protected API routes."""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status

from app.core import get_settings


async def require_admin_secret(
    x_admin_secret: str | None = Header(default=None, alias="X-Admin-Secret"),
) -> None:
    """Require the configured admin secret for protected routes."""
    expected_secret = get_settings().admin_auth_secret

    if x_admin_secret is None or not secrets.compare_digest(
        x_admin_secret,
        expected_secret,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin secret.",
        )
