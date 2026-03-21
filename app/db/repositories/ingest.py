"""Repositories for ingest job tracking and raw persistence."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import NormalizationError, RawIngestBatch, RawSourceRecord, SourceCheckpoint

_UNSET = object()
TERMINAL_BATCH_STATUSES = frozenset({"completed", "failed", "partial", "cancelled"})
ACTIVE_BATCH_STATUSES = frozenset({"pending", "running"})


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _copy_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    return deepcopy(dict(value))


def _validate_required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be blank.")
    return normalized


def _validate_non_negative(value: int, field_name: str) -> int:
    if value < 0:
        raise ValueError(f"{field_name} must be greater than or equal to zero.")
    return value


class RawIngestBatchRepository:
    """Persistence operations for raw ingest job batches."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_raw_ingest_batch(
        self,
        *,
        source_name: str,
        source_job_id: str,
        correlation_id: str | None = None,
        status: str = "pending",
        record_count: int = 0,
        raw_storage_uri: str | None = None,
        request_metadata: Mapping[str, Any] | None = None,
        ingest_started_at: datetime | None = None,
    ) -> RawIngestBatch:
        batch = RawIngestBatch(
            source_name=_validate_required_text(source_name, "source_name"),
            source_job_id=_validate_required_text(source_job_id, "source_job_id"),
            correlation_id=correlation_id,
            ingest_started_at=ingest_started_at or _utc_now(),
            status=_validate_required_text(status, "status"),
            record_count=_validate_non_negative(record_count, "record_count"),
            raw_storage_uri=raw_storage_uri,
            request_metadata=_copy_mapping(request_metadata),
            created_at=_utc_now(),
        )
        self.session.add(batch)
        self.session.flush()
        return batch

    def update_job_counts_and_status(
        self,
        batch: RawIngestBatch,
        *,
        status: str | None = None,
        record_count: int | None = None,
        record_count_delta: int | None = None,
        request_metadata: Mapping[str, Any] | None = None,
        raw_storage_uri: str | None | object = _UNSET,
        ingest_completed_at: datetime | None | object = _UNSET,
    ) -> RawIngestBatch:
        if record_count is not None and record_count_delta is not None:
            raise ValueError("Provide either record_count or record_count_delta, not both.")

        next_status = batch.status if status is None else _validate_required_text(status, "status")

        if record_count is not None:
            batch.record_count = _validate_non_negative(record_count, "record_count")
        elif record_count_delta is not None:
            batch.record_count = _validate_non_negative(
                (batch.record_count or 0) + record_count_delta,
                "record_count",
            )

        batch.status = next_status

        if request_metadata:
            merged_metadata = dict(batch.request_metadata or {})
            merged_metadata.update(_copy_mapping(request_metadata))
            batch.request_metadata = merged_metadata

        if raw_storage_uri is not _UNSET:
            batch.raw_storage_uri = raw_storage_uri

        if ingest_completed_at is not _UNSET:
            batch.ingest_completed_at = ingest_completed_at
        elif next_status in TERMINAL_BATCH_STATUSES:
            batch.ingest_completed_at = batch.ingest_completed_at or _utc_now()
        elif next_status in ACTIVE_BATCH_STATUSES:
            batch.ingest_completed_at = None

        self.session.flush()
        return batch


class RawSourceRecordRepository:
    """Persistence operations for immutable raw source payload records."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def write_raw_source_record(
        self,
        *,
        batch_id: int,
        source_name: str,
        source_record_id: str,
        raw_payload: Mapping[str, Any],
        source_record_version: str | None = None,
        source_record_hash: str | None = None,
        lookup_fields: Mapping[str, Any] | None = None,
        observed_at: datetime | None = None,
        ingested_at: datetime | None = None,
    ) -> RawSourceRecord:
        record = RawSourceRecord(
            batch_id=batch_id,
            source_name=_validate_required_text(source_name, "source_name"),
            source_record_id=_validate_required_text(source_record_id, "source_record_id"),
            source_record_version=source_record_version,
            source_record_hash=source_record_hash,
            raw_payload=_copy_mapping(raw_payload),
            lookup_fields=_copy_mapping(lookup_fields),
            observed_at=observed_at,
            ingested_at=ingested_at or _utc_now(),
        )
        self.session.add(record)
        self.session.flush()
        return record


class SourceCheckpointRepository:
    """Persistence operations for per-source checkpoint state."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def update_source_checkpoint(
        self,
        *,
        source_name: str,
        checkpoint_key: str,
        cursor_value: Mapping[str, Any],
        last_batch_id: int | None | object = _UNSET,
        last_polled_at: datetime | None | object = _UNSET,
    ) -> SourceCheckpoint:
        normalized_source_name = _validate_required_text(source_name, "source_name")
        normalized_checkpoint_key = _validate_required_text(checkpoint_key, "checkpoint_key")

        checkpoint = self.session.scalar(
            select(SourceCheckpoint).where(
                SourceCheckpoint.source_name == normalized_source_name,
                SourceCheckpoint.checkpoint_key == normalized_checkpoint_key,
            )
        )

        timestamp = _utc_now()
        cursor_payload = _copy_mapping(cursor_value)

        if checkpoint is None:
            checkpoint = SourceCheckpoint(
                source_name=normalized_source_name,
                checkpoint_key=normalized_checkpoint_key,
                cursor_value=cursor_payload,
                updated_at=timestamp,
                last_polled_at=timestamp if last_polled_at is _UNSET else last_polled_at,
            )
            if last_batch_id is not _UNSET:
                checkpoint.last_batch_id = last_batch_id
            self.session.add(checkpoint)
        else:
            checkpoint.cursor_value = cursor_payload
            checkpoint.updated_at = timestamp
            if last_batch_id is not _UNSET:
                checkpoint.last_batch_id = last_batch_id
            if last_polled_at is _UNSET:
                checkpoint.last_polled_at = timestamp
            else:
                checkpoint.last_polled_at = last_polled_at

        self.session.flush()
        return checkpoint


class NormalizationErrorRepository:
    """Persistence operations for normalization failures."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def write_normalization_error(
        self,
        *,
        source_name: str,
        error_code: str,
        error_message: str,
        batch_id: int | None = None,
        raw_source_record_id: int | None = None,
        source_job_id: str | None = None,
        correlation_id: str | None = None,
        error_context: Mapping[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> NormalizationError:
        error = NormalizationError(
            batch_id=batch_id,
            raw_source_record_id=raw_source_record_id,
            source_name=_validate_required_text(source_name, "source_name"),
            source_job_id=source_job_id,
            correlation_id=correlation_id,
            error_code=_validate_required_text(error_code, "error_code"),
            error_message=_validate_required_text(error_message, "error_message"),
            error_context=_copy_mapping(error_context),
            occurred_at=occurred_at or _utc_now(),
        )
        self.session.add(error)
        self.session.flush()
        return error


__all__ = [
    "ACTIVE_BATCH_STATUSES",
    "NormalizationErrorRepository",
    "RawIngestBatchRepository",
    "RawSourceRecordRepository",
    "SourceCheckpointRepository",
    "TERMINAL_BATCH_STATUSES",
]
