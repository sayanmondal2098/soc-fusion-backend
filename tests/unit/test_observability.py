from __future__ import annotations

import asyncio
import io
import json
import logging
import unittest
from typing import Any
from uuid import uuid4

from app.api.middleware import CorrelationIdMiddleware
from app.core import (
    CORRELATION_ID_HEADER,
    JsonLogFormatter,
    bind_log_context,
    clear_log_context,
    get_correlation_id,
    log_connector_event,
    log_export_job_event,
    log_scheduler_event,
    scheduler_job_context,
)


class StructuredLoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_log_context()
        self.stream = io.StringIO()
        self.logger = logging.getLogger(f"test.observability.{uuid4().hex}")
        self.logger.handlers.clear()
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        handler = logging.StreamHandler(self.stream)
        handler.setFormatter(JsonLogFormatter())
        self.logger.addHandler(handler)

    def tearDown(self) -> None:
        clear_log_context()
        self.logger.handlers.clear()

    def test_connector_logs_are_structured_json(self) -> None:
        with bind_log_context(correlation_id="corr-123", source_job_id="job-123"):
            log_connector_event(
                self.logger,
                "misp",
                "connector.pull.completed",
                records=7,
            )

        payload = self._read_log_lines()[0]

        self.assertEqual(payload["component"], "connector")
        self.assertEqual(payload["event"], "connector.pull.completed")
        self.assertEqual(payload["connector"], "misp")
        self.assertEqual(payload["records"], 7)
        self.assertEqual(payload["correlation_id"], "corr-123")
        self.assertEqual(payload["source_job_id"], "job-123")

    def test_scheduler_and_export_logs_share_job_context(self) -> None:
        with scheduler_job_context("nightly-export") as job_context:
            scheduler_context = log_scheduler_event(
                self.logger,
                "nightly-export",
                "job.started",
            )
            export_context = log_export_job_event(
                self.logger,
                "indicator-bundle",
                "export.completed",
                exported_records=12,
            )

        payloads = self._read_log_lines()

        self.assertEqual(scheduler_context.correlation_id, job_context.correlation_id)
        self.assertEqual(scheduler_context.source_job_id, job_context.source_job_id)
        self.assertEqual(export_context.correlation_id, job_context.correlation_id)
        self.assertEqual(export_context.source_job_id, job_context.source_job_id)
        self.assertEqual(payloads[0]["component"], "scheduler")
        self.assertEqual(payloads[0]["correlation_id"], job_context.correlation_id)
        self.assertEqual(payloads[0]["source_job_id"], job_context.source_job_id)
        self.assertEqual(payloads[1]["component"], "export")
        self.assertEqual(payloads[1]["correlation_id"], job_context.correlation_id)
        self.assertEqual(payloads[1]["source_job_id"], job_context.source_job_id)
        self.assertEqual(payloads[1]["exported_records"], 12)

    def _read_log_lines(self) -> list[dict[str, Any]]:
        return [
            json.loads(line)
            for line in self.stream.getvalue().splitlines()
            if line.strip()
        ]


class CorrelationIdMiddlewareTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_log_context()

    def test_middleware_generates_correlation_id_and_response_header(self) -> None:
        observed: dict[str, str] = {}

        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            observed["context_correlation_id"] = get_correlation_id() or ""
            observed["state_correlation_id"] = scope["state"]["correlation_id"]
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"{}",
                    "more_body": False,
                }
            )

        response_messages = self._run_request(
            middleware=CorrelationIdMiddleware(app),
            headers=[],
        )

        correlation_id = self._get_header_value(
            response_messages[0]["headers"],
            CORRELATION_ID_HEADER,
        )

        self.assertTrue(correlation_id)
        self.assertEqual(correlation_id, observed["context_correlation_id"])
        self.assertEqual(correlation_id, observed["state_correlation_id"])
        self.assertIsNone(get_correlation_id())

    def test_middleware_preserves_incoming_correlation_id(self) -> None:
        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            await send(
                {
                    "type": "http.response.start",
                    "status": 204,
                    "headers": [],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"",
                    "more_body": False,
                }
            )

        response_messages = self._run_request(
            middleware=CorrelationIdMiddleware(app),
            headers=[(b"x-correlation-id", b"incoming-correlation-id")],
        )

        correlation_id = self._get_header_value(
            response_messages[0]["headers"],
            CORRELATION_ID_HEADER,
        )

        self.assertEqual(correlation_id, "incoming-correlation-id")

    def _run_request(
        self,
        *,
        middleware: CorrelationIdMiddleware,
        headers: list[tuple[bytes, bytes]],
    ) -> list[dict[str, Any]]:
        messages: list[dict[str, Any]] = []
        request_messages = [{"type": "http.request", "body": b"", "more_body": False}]

        async def receive() -> dict[str, Any]:
            if request_messages:
                return request_messages.pop(0)
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            messages.append(message)

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/health",
            "headers": headers,
        }

        asyncio.run(middleware(scope, receive, send))
        return messages

    def _get_header_value(
        self,
        headers: list[tuple[bytes, bytes]],
        header_name: str,
    ) -> str | None:
        target = header_name.lower().encode("latin-1")
        for current_name, current_value in headers:
            if current_name.lower() == target:
                return current_value.decode("latin-1")
        return None


if __name__ == "__main__":
    unittest.main()
