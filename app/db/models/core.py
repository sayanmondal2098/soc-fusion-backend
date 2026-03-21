"""Core database models for ingestion, normalization, and export auditing."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RawIngestBatch(Base):
    __tablename__ = "raw_ingest_batch"

    id: Mapped[int] = mapped_column(
        BigInteger,
        Identity(),
        primary_key=True,
    )
    source_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source_job_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    ingest_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    ingest_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=text("'pending'"),
    )
    record_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0"),
    )
    raw_storage_uri: Mapped[str | None] = mapped_column(Text)
    request_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class RawSourceRecord(Base):
    __tablename__ = "raw_source_record"
    __table_args__ = (
        Index(
            "ix_raw_source_record_batch_source_record",
            "batch_id",
            "source_record_id",
        ),
        Index(
            "ix_raw_source_record_lookup_fields_gin",
            "lookup_fields",
            postgresql_using="gin",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    batch_id: Mapped[int] = mapped_column(
        ForeignKey("raw_ingest_batch.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source_record_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_record_version: Mapped[str | None] = mapped_column(String(128))
    source_record_hash: Mapped[str | None] = mapped_column(String(128))
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    lookup_fields: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class Indicator(Base):
    __tablename__ = "indicator"
    __table_args__ = (
        Index("ix_indicator_canonical_key", "canonical_key", unique=True),
        Index("ix_indicator_normalized_value", "normalized_value"),
        Index("ix_indicator_indicator_type", "indicator_type"),
        Index("ix_indicator_last_seen", "last_seen"),
        Index(
            "ix_indicator_type_normalized_value",
            "indicator_type",
            "normalized_value",
            unique=True,
        ),
        Index("ix_indicator_tags_gin", "tags", postgresql_using="gin"),
        Index(
            "ix_indicator_lookup_fields_gin",
            "lookup_fields",
            postgresql_using="gin",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    canonical_key: Mapped[str] = mapped_column(Text, nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False)
    display_value: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    confidence: Mapped[int | None] = mapped_column(SmallInteger)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text()),
        nullable=False,
        server_default=text("'{}'::text[]"),
    )
    lookup_fields: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    enrichment: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class IndicatorSourceLink(Base):
    __tablename__ = "indicator_source_link"
    __table_args__ = (
        Index(
            "ix_indicator_source_link_indicator_record",
            "indicator_id",
            "raw_source_record_id",
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicator.id", ondelete="CASCADE"),
        nullable=False,
    )
    raw_source_record_id: Mapped[int] = mapped_column(
        ForeignKey("raw_source_record.id", ondelete="CASCADE"),
        nullable=False,
    )
    link_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=text("'observed'"),
    )
    confidence: Mapped[int | None] = mapped_column(SmallInteger)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    source_context: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )


class SourceCheckpoint(Base):
    __tablename__ = "source_checkpoint"
    __table_args__ = (
        Index(
            "ix_source_checkpoint_source_checkpoint",
            "source_name",
            "checkpoint_key",
            unique=True,
        ),
        Index(
            "ix_source_checkpoint_cursor_value_gin",
            "cursor_value",
            postgresql_using="gin",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    checkpoint_key: Mapped[str] = mapped_column(String(150), nullable=False)
    cursor_value: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    last_batch_id: Mapped[int | None] = mapped_column(
        ForeignKey("raw_ingest_batch.id", ondelete="SET NULL")
    )
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class ExportAudit(Base):
    __tablename__ = "export_audit"
    __table_args__ = (
        Index("ix_export_audit_exported_at", "exported_at"),
        Index("ix_export_audit_filters_gin", "filters", postgresql_using="gin"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    source_job_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    export_job_name: Mapped[str] = mapped_column(String(150), nullable=False)
    export_target: Mapped[str] = mapped_column(String(150), nullable=False)
    exported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    record_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0"),
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=text("'pending'"),
    )
    filters: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    artifact_uri: Mapped[str | None] = mapped_column(Text)


class NormalizationError(Base):
    __tablename__ = "normalization_error"
    __table_args__ = (
        Index("ix_normalization_error_occurred_at", "occurred_at"),
        Index(
            "ix_normalization_error_error_context_gin",
            "error_context",
            postgresql_using="gin",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    batch_id: Mapped[int | None] = mapped_column(
        ForeignKey("raw_ingest_batch.id", ondelete="SET NULL")
    )
    raw_source_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("raw_source_record.id", ondelete="SET NULL")
    )
    source_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source_job_id: Mapped[str | None] = mapped_column(String(255))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    error_code: Mapped[str] = mapped_column(String(100), nullable=False)
    error_message: Mapped[str] = mapped_column(Text, nullable=False)
    error_context: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
