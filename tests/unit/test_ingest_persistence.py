from __future__ import annotations

import io
import json
import logging
import unittest
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.core import JsonLogFormatter, clear_log_context
from app.db.models import RawIngestBatch, SourceCheckpoint
from app.db.repositories import (
    NormalizationErrorRepository,
    RawIngestBatchRepository,
    RawSourceRecordRepository,
    SourceCheckpointRepository,
)
from app.services import IngestPersistenceService


class SessionDouble:
    def __init__(self) -> None:
        self.added: list[Any] = []
        self.flush_count = 0
        self.scalar_result: Any = None
        self.last_scalar_statement: Any = None
        self._next_identity = 1

    def add(self, instance: Any) -> None:
        self.added.append(instance)

    def flush(self) -> None:
        self.flush_count += 1
        for instance in self.added:
            if getattr(instance, "id", None) is None:
                setattr(instance, "id", self._next_identity)
                self._next_identity += 1

    def scalar(self, statement: Any) -> Any:
        self.last_scalar_statement = statement
        return self.scalar_result


class RawIngestBatchRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session = SessionDouble()
        self.repository = RawIngestBatchRepository(self.session)

    def test_create_raw_ingest_batch_persists_defaults(self) -> None:
        batch = self.repository.create_raw_ingest_batch(
            source_name="otx",
            source_job_id="otx:job-001",
            correlation_id="corr-001",
            request_metadata={"page": 1},
        )

        self.assertEqual(batch.id, 1)
        self.assertEqual(batch.status, "pending")
        self.assertEqual(batch.record_count, 0)
        self.assertEqual(batch.request_metadata, {"page": 1})
        self.assertEqual(batch.correlation_id, "corr-001")
        self.assertEqual(self.session.flush_count, 1)

    def test_update_job_counts_and_status_tracks_terminal_completion(self) -> None:
        batch = RawIngestBatch(
            source_name="otx",
            source_job_id="otx:job-002",
            correlation_id="corr-002",
            status="running",
            record_count=2,
            request_metadata={"page": 2},
        )

        updated_batch = self.repository.update_job_counts_and_status(
            batch,
            status="completed",
            record_count_delta=3,
            request_metadata={"records_seen": 5},
            raw_storage_uri="file:///tmp/otx/20260322.json",
        )

        self.assertIs(updated_batch, batch)
        self.assertEqual(updated_batch.record_count, 5)
        self.assertEqual(updated_batch.status, "completed")
        self.assertEqual(
            updated_batch.request_metadata,
            {"page": 2, "records_seen": 5},
        )
        self.assertEqual(
            updated_batch.raw_storage_uri,
            "file:///tmp/otx/20260322.json",
        )
        self.assertIsNotNone(updated_batch.ingest_completed_at)


class RawSourceRecordRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session = SessionDouble()
        self.repository = RawSourceRecordRepository(self.session)

    def test_write_raw_source_record_copies_payloads(self) -> None:
        raw_payload = {"indicator": "example.org", "nested": {"confidence": 80}}
        lookup_fields = {"domain": "example.org"}

        record = self.repository.write_raw_source_record(
            batch_id=11,
            source_name="misp",
            source_record_id="event-10",
            source_record_version="2",
            source_record_hash="sha256:abc",
            raw_payload=raw_payload,
            lookup_fields=lookup_fields,
        )

        raw_payload["nested"]["confidence"] = 1
        lookup_fields["domain"] = "mutated.example"

        self.assertEqual(record.id, 1)
        self.assertEqual(record.batch_id, 11)
        self.assertEqual(record.source_name, "misp")
        self.assertEqual(record.raw_payload["nested"]["confidence"], 80)
        self.assertEqual(record.lookup_fields["domain"], "example.org")


class SourceCheckpointRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session = SessionDouble()
        self.repository = SourceCheckpointRepository(self.session)

    def test_update_source_checkpoint_creates_missing_row(self) -> None:
        checkpoint = self.repository.update_source_checkpoint(
            source_name="otx",
            checkpoint_key="since",
            cursor_value={"modified_since": "2026-03-21T00:00:00Z"},
            last_batch_id=22,
        )

        self.assertEqual(checkpoint.id, 1)
        self.assertEqual(checkpoint.source_name, "otx")
        self.assertEqual(checkpoint.checkpoint_key, "since")
        self.assertEqual(checkpoint.cursor_value["modified_since"], "2026-03-21T00:00:00Z")
        self.assertEqual(checkpoint.last_batch_id, 22)
        self.assertIsNotNone(checkpoint.last_polled_at)

    def test_update_source_checkpoint_updates_existing_row(self) -> None:
        existing = SourceCheckpoint(
            id=8,
            source_name="misp",
            checkpoint_key="feed",
            cursor_value={"page": 1},
            last_batch_id=4,
            last_polled_at=datetime(2026, 3, 21, tzinfo=UTC),
            updated_at=datetime(2026, 3, 21, tzinfo=UTC),
        )
        self.session.scalar_result = existing

        checkpoint = self.repository.update_source_checkpoint(
            source_name="misp",
            checkpoint_key="feed",
            cursor_value={"page": 2},
            last_batch_id=9,
        )

        self.assertIs(checkpoint, existing)
        self.assertEqual(checkpoint.cursor_value, {"page": 2})
        self.assertEqual(checkpoint.last_batch_id, 9)


class NormalizationErrorRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session = SessionDouble()
        self.repository = NormalizationErrorRepository(self.session)

    def test_write_normalization_error_persists_context(self) -> None:
        error = self.repository.write_normalization_error(
            batch_id=3,
            raw_source_record_id=7,
            source_name="misp",
            source_job_id="misp:job-004",
            correlation_id="corr-004",
            error_code="missing_type",
            error_message="The source payload did not include a type.",
            error_context={"field": "type"},
        )

        self.assertEqual(error.id, 1)
        self.assertEqual(error.batch_id, 3)
        self.assertEqual(error.raw_source_record_id, 7)
        self.assertEqual(error.error_context, {"field": "type"})


class IngestPersistenceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_log_context()
        self.session = SessionDouble()
        self.service = IngestPersistenceService(self.session)
        self.log_stream = io.StringIO()
        self.logger = logging.getLogger(f"test.ingest.persistence.{uuid4().hex}")
        self.logger.handlers.clear()
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        handler = logging.StreamHandler(self.log_stream)
        handler.setFormatter(JsonLogFormatter())
        self.logger.addHandler(handler)
        self.service.logger = self.logger

    def tearDown(self) -> None:
        clear_log_context()
        self.logger.handlers.clear()

    def test_create_raw_ingest_batch_generates_scheduler_context(self) -> None:
        batch = self.service.create_raw_ingest_batch(source_name="otx")

        self.assertEqual(batch.id, 1)
        self.assertEqual(batch.source_name, "otx")
        self.assertEqual(batch.status, "pending")
        self.assertTrue(batch.correlation_id)
        self.assertTrue(batch.source_job_id.startswith("otx:"))

        payload = self._read_log_lines()[0]
        self.assertEqual(payload["component"], "scheduler")
        self.assertEqual(payload["event"], "ingest.batch.created")
        self.assertEqual(payload["batch_id"], 1)
        self.assertEqual(payload["correlation_id"], batch.correlation_id)
        self.assertEqual(payload["source_job_id"], batch.source_job_id)

    def test_write_raw_source_record_and_checkpoint_follow_batch_context(self) -> None:
        batch = self.service.create_raw_ingest_batch(
            source_name="misp",
            source_job_id="misp:job-005",
            correlation_id="corr-005",
        )

        record = self.service.write_raw_source_record(
            batch,
            source_record_id="event-500",
            raw_payload={"id": 500},
            lookup_fields={"event_id": 500},
        )
        checkpoint = self.service.update_source_checkpoint(
            batch,
            checkpoint_key="event_feed",
            cursor_value={"last_event_id": 500},
        )

        self.assertEqual(record.batch_id, batch.id)
        self.assertEqual(record.source_name, "misp")
        self.assertEqual(checkpoint.last_batch_id, batch.id)

        payloads = self._read_log_lines()
        self.assertEqual(payloads[1]["component"], "connector")
        self.assertEqual(payloads[1]["event"], "raw.record.stored")
        self.assertEqual(payloads[1]["correlation_id"], "corr-005")
        self.assertEqual(payloads[1]["source_job_id"], "misp:job-005")
        self.assertEqual(payloads[2]["component"], "scheduler")
        self.assertEqual(payloads[2]["event"], "source.checkpoint.updated")

    def test_write_normalization_error_uses_batch_identifiers(self) -> None:
        batch = self.service.create_raw_ingest_batch(
            source_name="otx",
            source_job_id="otx:job-006",
            correlation_id="corr-006",
        )

        error = self.service.write_normalization_error(
            batch,
            error_code="unsupported_indicator_type",
            error_message="Observed indicator type was not recognized.",
            raw_source_record_id=12,
            error_context={"indicator_type": "unknown"},
        )

        self.assertEqual(error.batch_id, batch.id)
        self.assertEqual(error.source_job_id, "otx:job-006")
        self.assertEqual(error.correlation_id, "corr-006")

        payload = self._read_log_lines()[-1]
        self.assertEqual(payload["component"], "connector")
        self.assertEqual(payload["event"], "normalization.error.recorded")
        self.assertEqual(payload["error_code"], "unsupported_indicator_type")
        self.assertEqual(payload["raw_source_record_id"], 12)

    def _read_log_lines(self) -> list[dict[str, Any]]:
        return [
            json.loads(line)
            for line in self.log_stream.getvalue().splitlines()
            if line.strip()
        ]


if __name__ == "__main__":
    unittest.main()
