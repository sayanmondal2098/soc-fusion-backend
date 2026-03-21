"""Structured JSON logging and correlation helpers."""

from __future__ import annotations

import json
import logging
import sys
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

CORRELATION_ID_HEADER = "X-Correlation-ID"

_UNSET = object()
_correlation_id_var: ContextVar[str | None] = ContextVar(
    "correlation_id",
    default=None,
)
_source_job_id_var: ContextVar[str | None] = ContextVar(
    "source_job_id",
    default=None,
)
_RESERVED_LOG_RECORD_FIELDS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "message",
    "module",
    "msecs",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
    "taskName",
}
_JSON_HANDLER_NAME = "soc-fusion-json-handler"


@dataclass(slots=True, frozen=True)
class JobLogContext:
    correlation_id: str
    source_job_id: str


class JsonLogFormatter(logging.Formatter):
    """Render log records as single-line JSON payloads."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        correlation_id = getattr(record, "correlation_id", None) or get_correlation_id()
        source_job_id = getattr(record, "source_job_id", None) or get_source_job_id()

        if correlation_id is not None:
            payload["correlation_id"] = correlation_id
        if source_job_id is not None:
            payload["source_job_id"] = source_job_id

        for field in (
            "component",
            "event",
            "connector",
            "job_name",
            "export_job",
            "method",
            "path",
            "status_code",
            "duration_ms",
            "environment",
        ):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = _serialize_log_value(value)

        for key, value in record.__dict__.items():
            if key in _RESERVED_LOG_RECORD_FIELDS or key in payload:
                continue
            payload[key] = _serialize_log_value(value)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, separators=(",", ":"))


def configure_logging(*, debug: bool = False) -> None:
    """Configure root logging to emit structured JSON."""
    root_logger = logging.getLogger()
    log_level = logging.DEBUG if debug else logging.INFO
    root_logger.setLevel(log_level)

    for handler in root_logger.handlers:
        if getattr(handler, "name", None) == _JSON_HANDLER_NAME:
            handler.setLevel(log_level)
            handler.setFormatter(JsonLogFormatter())
            return

    handler = logging.StreamHandler(sys.stdout)
    handler.set_name(_JSON_HANDLER_NAME)
    handler.setLevel(log_level)
    handler.setFormatter(JsonLogFormatter())

    root_logger.handlers.clear()
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger for a service component."""
    return logging.getLogger(name)


def generate_correlation_id() -> str:
    """Generate a correlation ID suitable for headers and logs."""
    return uuid4().hex


def get_correlation_id() -> str | None:
    """Return the correlation ID bound to the current context, if any."""
    return _correlation_id_var.get()


def get_source_job_id() -> str | None:
    """Return the source job ID bound to the current context, if any."""
    return _source_job_id_var.get()


@contextmanager
def bind_log_context(
    *,
    correlation_id: str | None | object = _UNSET,
    source_job_id: str | None | object = _UNSET,
) -> Iterator[None]:
    """Bind correlation and job identifiers to the current execution context."""
    tokens: list[tuple[ContextVar[str | None], Token[str | None]]] = []
    try:
        if correlation_id is not _UNSET:
            tokens.append(
                (
                    _correlation_id_var,
                    _correlation_id_var.set(_coerce_context_value(correlation_id)),
                )
            )
        if source_job_id is not _UNSET:
            tokens.append(
                (
                    _source_job_id_var,
                    _source_job_id_var.set(_coerce_context_value(source_job_id)),
                )
            )
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


def clear_log_context() -> None:
    """Clear all request or job-scoped log context."""
    _correlation_id_var.set(None)
    _source_job_id_var.set(None)


def build_job_log_context(
    job_name: str,
    *,
    source_job_id: str | None = None,
    correlation_id: str | None = None,
) -> JobLogContext:
    """Resolve correlation and job identifiers for a scheduler or export job."""
    resolved_correlation_id = (
        correlation_id or get_correlation_id() or generate_correlation_id()
    )
    resolved_source_job_id = (
        source_job_id or get_source_job_id() or f"{job_name}:{uuid4().hex}"
    )
    return JobLogContext(
        correlation_id=resolved_correlation_id,
        source_job_id=resolved_source_job_id,
    )


@contextmanager
def scheduler_job_context(
    job_name: str,
    *,
    source_job_id: str | None = None,
    correlation_id: str | None = None,
) -> Iterator[JobLogContext]:
    """Bind a correlation ID and source job ID for scheduler work."""
    context = build_job_log_context(
        job_name,
        source_job_id=source_job_id,
        correlation_id=correlation_id,
    )
    with bind_log_context(
        correlation_id=context.correlation_id,
        source_job_id=context.source_job_id,
    ):
        yield context


def log_api_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    correlation_id: str | None = None,
    **fields: Any,
) -> None:
    """Emit a structured API log event."""
    _emit_component_log(
        logger,
        component="api",
        event=event,
        level=level,
        correlation_id=correlation_id if correlation_id is not None else _UNSET,
        **fields,
    )


def log_connector_event(
    logger: logging.Logger,
    connector: str,
    event: str,
    *,
    level: int = logging.INFO,
    source_job_id: str | None = None,
    correlation_id: str | None = None,
    **fields: Any,
) -> None:
    """Emit a structured connector log event."""
    _emit_component_log(
        logger,
        component="connector",
        event=event,
        level=level,
        connector=connector,
        correlation_id=correlation_id if correlation_id is not None else _UNSET,
        source_job_id=source_job_id if source_job_id is not None else _UNSET,
        **fields,
    )


def log_scheduler_event(
    logger: logging.Logger,
    job_name: str,
    event: str,
    *,
    level: int = logging.INFO,
    source_job_id: str | None = None,
    correlation_id: str | None = None,
    **fields: Any,
) -> JobLogContext:
    """Emit a structured scheduler log event and ensure job correlation context."""
    context = build_job_log_context(
        job_name,
        source_job_id=source_job_id,
        correlation_id=correlation_id,
    )
    _emit_component_log(
        logger,
        component="scheduler",
        event=event,
        level=level,
        correlation_id=context.correlation_id,
        source_job_id=context.source_job_id,
        job_name=job_name,
        **fields,
    )
    return context


def log_export_job_event(
    logger: logging.Logger,
    export_job: str,
    event: str,
    *,
    level: int = logging.INFO,
    source_job_id: str | None = None,
    correlation_id: str | None = None,
    **fields: Any,
) -> JobLogContext:
    """Emit a structured export job log event and ensure job correlation context."""
    context = build_job_log_context(
        export_job,
        source_job_id=source_job_id,
        correlation_id=correlation_id,
    )
    _emit_component_log(
        logger,
        component="export",
        event=event,
        level=level,
        correlation_id=context.correlation_id,
        source_job_id=context.source_job_id,
        export_job=export_job,
        **fields,
    )
    return context


def _emit_component_log(
    logger: logging.Logger,
    *,
    component: str,
    event: str,
    level: int,
    correlation_id: str | None | object = _UNSET,
    source_job_id: str | None | object = _UNSET,
    **fields: Any,
) -> None:
    extra = {"component": component, "event": event}
    for key, value in fields.items():
        if value is not None:
            extra[key] = value

    context = (
        bind_log_context(
            correlation_id=correlation_id,
            source_job_id=source_job_id,
        )
        if correlation_id is not _UNSET or source_job_id is not _UNSET
        else nullcontext()
    )

    with context:
        logger.log(level, event, extra=extra)


def _serialize_log_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _serialize_log_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serialize_log_value(item) for item in value]
    return str(value)


def _coerce_context_value(value: str | None | object) -> str | None:
    if value is None or value is _UNSET:
        return None
    return str(value)


__all__ = [
    "CORRELATION_ID_HEADER",
    "JobLogContext",
    "JsonLogFormatter",
    "bind_log_context",
    "build_job_log_context",
    "clear_log_context",
    "configure_logging",
    "generate_correlation_id",
    "get_correlation_id",
    "get_logger",
    "get_source_job_id",
    "log_api_event",
    "log_connector_event",
    "log_export_job_event",
    "log_scheduler_event",
    "scheduler_job_context",
]
