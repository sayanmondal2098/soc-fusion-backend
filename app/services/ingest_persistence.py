"""Service methods for scheduler-driven ingest tracking and raw persistence."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from contextlib import AbstractContextManager
from datetime import datetime

from sqlalchemy.orm import Session

from app.core import (
    bind_log_context,
    build_job_log_context,
    get_logger,
    log_connector_event,
    log_scheduler_event,
)
from app.db.models import NormalizationError, RawIngestBatch, RawSourceRecord, SourceCheckpoint
from app.db.repositories import (
    NormalizationErrorRepository,
    RawIngestBatchRepository,
    RawSourceRecordRepository,
    SourceCheckpointRepository,
)

_UNSET = object()


class IngestPersistenceService:
    """Coordinate ingest job tracking and raw persistence before normalization or fusion."""

    def __init__(
        self,
        session: Session,
        *,
        batch_repository: RawIngestBatchRepository | None = None,
        raw_record_repository: RawSourceRecordRepository | None = None,
        checkpoint_repository: SourceCheckpointRepository | None = None,
        normalization_error_repository: NormalizationErrorRepository | None = None,
    ) -> None:
        self.session = session
        self.batch_repository = batch_repository or RawIngestBatchRepository(session)
        self.raw_record_repository = raw_record_repository or RawSourceRecordRepository(session)
        self.checkpoint_repository = checkpoint_repository or SourceCheckpointRepository(session)
        self.normalization_error_repository = (
            normalization_error_repository or NormalizationErrorRepository(session)
        )
        self.logger = get_logger("soc_fusion.services.ingest_persistence")

    def create_raw_ingest_batch(
        self,
        *,
        source_name: str,
        source_job_id: str | None = None,
        correlation_id: str | None = None,
        status: str = "pending",
        record_count: int = 0,
        raw_storage_uri: str | None = None,
        request_metadata: Mapping[str, object] | None = None,
    ) -> RawIngestBatch:
        job_context = build_job_log_context(
            source_name,
            source_job_id=source_job_id,
            correlation_id=correlation_id,
        )
        with bind_log_context(
            correlation_id=job_context.correlation_id,
            source_job_id=job_context.source_job_id,
        ):
            batch = self.batch_repository.create_raw_ingest_batch(
                source_name=source_name,
                source_job_id=job_context.source_job_id,
                correlation_id=job_context.correlation_id,
                status=status,
                record_count=record_count,
                raw_storage_uri=raw_storage_uri,
                request_metadata=request_metadata,
            )
            log_scheduler_event(
                self.logger,
                source_name,
                "ingest.batch.created",
                source_job_id=batch.source_job_id,
                correlation_id=batch.correlation_id,
                batch_id=batch.id,
                status=batch.status,
                record_count=batch.record_count,
            )
            return batch

    def update_job_counts_and_status(
        self,
        batch: RawIngestBatch,
        *,
        status: str | None = None,
        record_count: int | None = None,
        record_count_delta: int | None = None,
        request_metadata: Mapping[str, object] | None = None,
        raw_storage_uri: str | None | object = _UNSET,
    ) -> RawIngestBatch:
        repository_kwargs: dict[str, object] = {
            "status": status,
            "record_count": record_count,
            "record_count_delta": record_count_delta,
            "request_metadata": request_metadata,
        }
        if raw_storage_uri is not _UNSET:
            repository_kwargs["raw_storage_uri"] = raw_storage_uri

        with self._bind_batch_context(batch):
            updated_batch = self.batch_repository.update_job_counts_and_status(
                batch,
                **repository_kwargs,
            )
            log_scheduler_event(
                self.logger,
                batch.source_name,
                "ingest.batch.updated",
                source_job_id=batch.source_job_id,
                correlation_id=batch.correlation_id,
                batch_id=batch.id,
                status=updated_batch.status,
                record_count=updated_batch.record_count,
            )
            return updated_batch

    def write_raw_source_record(
        self,
        batch: RawIngestBatch,
        *,
        source_record_id: str,
        raw_payload: Mapping[str, object],
        source_record_version: str | None = None,
        source_record_hash: str | None = None,
        lookup_fields: Mapping[str, object] | None = None,
        observed_at: datetime | None = None,
    ) -> RawSourceRecord:
        with self._bind_batch_context(batch):
            record = self.raw_record_repository.write_raw_source_record(
                batch_id=batch.id,
                source_name=batch.source_name,
                source_record_id=source_record_id,
                raw_payload=raw_payload,
                source_record_version=source_record_version,
                source_record_hash=source_record_hash,
                lookup_fields=lookup_fields,
                observed_at=observed_at,
            )
            log_connector_event(
                self.logger,
                batch.source_name,
                "raw.record.stored",
                source_job_id=batch.source_job_id,
                correlation_id=batch.correlation_id,
                batch_id=batch.id,
                raw_source_record_id=record.id,
                source_record_id=record.source_record_id,
            )
            return record

    def update_source_checkpoint(
        self,
        batch: RawIngestBatch,
        *,
        checkpoint_key: str,
        cursor_value: Mapping[str, object],
        last_batch_id: int | None | object = _UNSET,
        last_polled_at: datetime | None | object = _UNSET,
    ) -> SourceCheckpoint:
        repository_kwargs: dict[str, object] = {
            "source_name": batch.source_name,
            "checkpoint_key": checkpoint_key,
            "cursor_value": cursor_value,
            "last_batch_id": batch.id if last_batch_id is _UNSET else last_batch_id,
        }
        if last_polled_at is not _UNSET:
            repository_kwargs["last_polled_at"] = last_polled_at

        with self._bind_batch_context(batch):
            checkpoint = self.checkpoint_repository.update_source_checkpoint(
                **repository_kwargs,
            )
            log_scheduler_event(
                self.logger,
                batch.source_name,
                "source.checkpoint.updated",
                source_job_id=batch.source_job_id,
                correlation_id=batch.correlation_id,
                batch_id=batch.id,
                checkpoint_key=checkpoint_key,
                last_batch_id=checkpoint.last_batch_id,
            )
            return checkpoint

    def write_normalization_error(
        self,
        batch: RawIngestBatch,
        *,
        error_code: str,
        error_message: str,
        raw_source_record: RawSourceRecord | None = None,
        raw_source_record_id: int | None = None,
        error_context: Mapping[str, object] | None = None,
        occurred_at: datetime | None = None,
    ) -> NormalizationError:
        resolved_raw_source_record_id = (
            raw_source_record.id if raw_source_record is not None else raw_source_record_id
        )

        with self._bind_batch_context(batch):
            error = self.normalization_error_repository.write_normalization_error(
                batch_id=batch.id,
                raw_source_record_id=resolved_raw_source_record_id,
                source_name=batch.source_name,
                source_job_id=batch.source_job_id,
                correlation_id=batch.correlation_id,
                error_code=error_code,
                error_message=error_message,
                error_context=error_context,
                occurred_at=occurred_at,
            )
            log_connector_event(
                self.logger,
                batch.source_name,
                "normalization.error.recorded",
                level=logging.WARNING,
                source_job_id=batch.source_job_id,
                correlation_id=batch.correlation_id,
                batch_id=batch.id,
                raw_source_record_id=resolved_raw_source_record_id,
                error_code=error.error_code,
            )
            return error

    @staticmethod
    def _bind_batch_context(
        batch: RawIngestBatch,
    ) -> AbstractContextManager[None]:
        return bind_log_context(
            correlation_id=batch.correlation_id,
            source_job_id=batch.source_job_id,
        )


__all__ = ["IngestPersistenceService"]
