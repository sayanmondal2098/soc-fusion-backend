"""ASGI middleware for request correlation and request logging."""

from __future__ import annotations

import logging
from time import perf_counter
from typing import Any, Awaitable, Callable

from app.core import (
    CORRELATION_ID_HEADER,
    bind_log_context,
    generate_correlation_id,
    get_logger,
    log_api_event,
)

ASGIMessage = dict[str, Any]
Receive = Callable[[], Awaitable[ASGIMessage]]
Send = Callable[[ASGIMessage], Awaitable[None]]

_CORRELATION_ID_HEADER_BYTES = CORRELATION_ID_HEADER.lower().encode("latin-1")


class CorrelationIdMiddleware:
    """Ensure each HTTP request has a correlation ID and response header."""

    def __init__(self, app: Callable[[dict[str, Any], Receive, Send], Awaitable[None]]) -> None:
        self.app = app
        self.logger = get_logger("soc_fusion.api.request")

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        correlation_id = _extract_correlation_id(scope) or generate_correlation_id()
        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "")
        started_at = perf_counter()
        response_status = 500

        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["correlation_id"] = correlation_id

        with bind_log_context(correlation_id=correlation_id):
            log_api_event(
                self.logger,
                "request.started",
                method=method,
                path=path,
            )

            async def send_with_correlation_id(message: ASGIMessage) -> None:
                nonlocal response_status

                if message.get("type") == "http.response.start":
                    response_status = int(message.get("status", 500))
                    headers = _set_header(
                        list(message.get("headers", [])),
                        _CORRELATION_ID_HEADER_BYTES,
                        correlation_id.encode("latin-1"),
                    )
                    message = {**message, "headers": headers}

                await send(message)

            try:
                await self.app(scope, receive, send_with_correlation_id)
            except Exception as exc:
                duration_ms = round((perf_counter() - started_at) * 1000, 2)
                log_api_event(
                    self.logger,
                    "request.failed",
                    level=logging.ERROR,
                    method=method,
                    path=path,
                    status_code=500,
                    duration_ms=duration_ms,
                    error=type(exc).__name__,
                )
                raise
            else:
                duration_ms = round((perf_counter() - started_at) * 1000, 2)
                log_api_event(
                    self.logger,
                    "request.completed",
                    method=method,
                    path=path,
                    status_code=response_status,
                    duration_ms=duration_ms,
                )


def _extract_correlation_id(scope: dict[str, Any]) -> str | None:
    for header_name, header_value in scope.get("headers", []):
        if header_name.lower() == _CORRELATION_ID_HEADER_BYTES:
            return header_value.decode("latin-1")
    return None


def _set_header(
    headers: list[tuple[bytes, bytes]],
    header_name: bytes,
    header_value: bytes,
) -> list[tuple[bytes, bytes]]:
    filtered_headers = [
        (existing_name, existing_value)
        for existing_name, existing_value in headers
        if existing_name.lower() != header_name
    ]
    filtered_headers.append((header_name, header_value))
    return filtered_headers
