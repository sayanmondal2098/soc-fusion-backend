"""Create core ingest, indicator, checkpoint, audit, and error tables."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260321_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "raw_ingest_batch",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("source_name", sa.String(length=100), nullable=False),
        sa.Column("source_job_id", sa.String(length=255), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column(
            "ingest_started_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("ingest_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "record_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("raw_storage_uri", sa.Text(), nullable=True),
        sa.Column(
            "request_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_raw_ingest_batch")),
    )
    op.create_index(
        op.f("ix_raw_ingest_batch_source_name"),
        "raw_ingest_batch",
        ["source_name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_ingest_batch_source_job_id"),
        "raw_ingest_batch",
        ["source_job_id"],
        unique=True,
    )

    op.create_table(
        "raw_source_record",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("batch_id", sa.BigInteger(), nullable=False),
        sa.Column("source_name", sa.String(length=100), nullable=False),
        sa.Column("source_record_id", sa.String(length=255), nullable=False),
        sa.Column("source_record_version", sa.String(length=128), nullable=True),
        sa.Column("source_record_hash", sa.String(length=128), nullable=True),
        sa.Column("raw_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "lookup_fields",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["batch_id"],
            ["raw_ingest_batch.id"],
            name=op.f("fk_raw_source_record_batch_id_raw_ingest_batch"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_raw_source_record")),
    )
    op.create_index(
        op.f("ix_raw_source_record_source_name"),
        "raw_source_record",
        ["source_name"],
        unique=False,
    )
    op.create_index(
        "ix_raw_source_record_batch_source_record",
        "raw_source_record",
        ["batch_id", "source_record_id"],
        unique=False,
    )
    op.create_index(
        "ix_raw_source_record_lookup_fields_gin",
        "raw_source_record",
        ["lookup_fields"],
        unique=False,
        postgresql_using="gin",
    )

    op.create_table(
        "indicator",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("canonical_key", sa.Text(), nullable=False),
        sa.Column("indicator_type", sa.String(length=64), nullable=False),
        sa.Column("normalized_value", sa.Text(), nullable=False),
        sa.Column("display_value", sa.Text(), nullable=True),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("confidence", sa.SmallInteger(), nullable=True),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column(
            "lookup_fields",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "enrichment",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_indicator")),
    )
    op.create_index(
        "ix_indicator_canonical_key",
        "indicator",
        ["canonical_key"],
        unique=True,
    )
    op.create_index(
        "ix_indicator_normalized_value",
        "indicator",
        ["normalized_value"],
        unique=False,
    )
    op.create_index(
        "ix_indicator_indicator_type",
        "indicator",
        ["indicator_type"],
        unique=False,
    )
    op.create_index(
        "ix_indicator_last_seen",
        "indicator",
        ["last_seen"],
        unique=False,
    )
    op.create_index(
        "ix_indicator_type_normalized_value",
        "indicator",
        ["indicator_type", "normalized_value"],
        unique=True,
    )
    op.create_index(
        "ix_indicator_tags_gin",
        "indicator",
        ["tags"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_indicator_lookup_fields_gin",
        "indicator",
        ["lookup_fields"],
        unique=False,
        postgresql_using="gin",
    )

    op.create_table(
        "indicator_source_link",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("indicator_id", sa.BigInteger(), nullable=False),
        sa.Column("raw_source_record_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "link_type",
            sa.String(length=32),
            server_default=sa.text("'observed'"),
            nullable=False,
        ),
        sa.Column("confidence", sa.SmallInteger(), nullable=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "source_context",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicator.id"],
            name=op.f("fk_indicator_source_link_indicator_id_indicator"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["raw_source_record_id"],
            ["raw_source_record.id"],
            name=op.f("fk_indicator_source_link_raw_source_record_id_raw_source_record"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_indicator_source_link")),
    )
    op.create_index(
        "ix_indicator_source_link_indicator_record",
        "indicator_source_link",
        ["indicator_id", "raw_source_record_id"],
        unique=True,
    )

    op.create_table(
        "source_checkpoint",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("source_name", sa.String(length=100), nullable=False),
        sa.Column("checkpoint_key", sa.String(length=150), nullable=False),
        sa.Column(
            "cursor_value",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("last_batch_id", sa.BigInteger(), nullable=True),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["last_batch_id"],
            ["raw_ingest_batch.id"],
            name=op.f("fk_source_checkpoint_last_batch_id_raw_ingest_batch"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_source_checkpoint")),
    )
    op.create_index(
        "ix_source_checkpoint_source_checkpoint",
        "source_checkpoint",
        ["source_name", "checkpoint_key"],
        unique=True,
    )
    op.create_index(
        "ix_source_checkpoint_cursor_value_gin",
        "source_checkpoint",
        ["cursor_value"],
        unique=False,
        postgresql_using="gin",
    )

    op.create_table(
        "export_audit",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("source_job_id", sa.String(length=255), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("export_job_name", sa.String(length=150), nullable=False),
        sa.Column("export_target", sa.String(length=150), nullable=False),
        sa.Column(
            "exported_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "record_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "filters",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("artifact_uri", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_export_audit")),
    )
    op.create_index(
        op.f("ix_export_audit_source_job_id"),
        "export_audit",
        ["source_job_id"],
        unique=False,
    )
    op.create_index(
        "ix_export_audit_exported_at",
        "export_audit",
        ["exported_at"],
        unique=False,
    )
    op.create_index(
        "ix_export_audit_filters_gin",
        "export_audit",
        ["filters"],
        unique=False,
        postgresql_using="gin",
    )

    op.create_table(
        "normalization_error",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("batch_id", sa.BigInteger(), nullable=True),
        sa.Column("raw_source_record_id", sa.BigInteger(), nullable=True),
        sa.Column("source_name", sa.String(length=100), nullable=False),
        sa.Column("source_job_id", sa.String(length=255), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=False),
        sa.Column(
            "error_context",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["batch_id"],
            ["raw_ingest_batch.id"],
            name=op.f("fk_normalization_error_batch_id_raw_ingest_batch"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["raw_source_record_id"],
            ["raw_source_record.id"],
            name=op.f("fk_normalization_error_raw_source_record_id_raw_source_record"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_normalization_error")),
    )
    op.create_index(
        op.f("ix_normalization_error_source_name"),
        "normalization_error",
        ["source_name"],
        unique=False,
    )
    op.create_index(
        "ix_normalization_error_occurred_at",
        "normalization_error",
        ["occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_normalization_error_error_context_gin",
        "normalization_error",
        ["error_context"],
        unique=False,
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_normalization_error_error_context_gin", table_name="normalization_error")
    op.drop_index("ix_normalization_error_occurred_at", table_name="normalization_error")
    op.drop_index(op.f("ix_normalization_error_source_name"), table_name="normalization_error")
    op.drop_table("normalization_error")

    op.drop_index("ix_export_audit_filters_gin", table_name="export_audit")
    op.drop_index("ix_export_audit_exported_at", table_name="export_audit")
    op.drop_index(op.f("ix_export_audit_source_job_id"), table_name="export_audit")
    op.drop_table("export_audit")

    op.drop_index("ix_source_checkpoint_cursor_value_gin", table_name="source_checkpoint")
    op.drop_index("ix_source_checkpoint_source_checkpoint", table_name="source_checkpoint")
    op.drop_table("source_checkpoint")

    op.drop_index("ix_indicator_source_link_indicator_record", table_name="indicator_source_link")
    op.drop_table("indicator_source_link")

    op.drop_index("ix_indicator_lookup_fields_gin", table_name="indicator")
    op.drop_index("ix_indicator_tags_gin", table_name="indicator")
    op.drop_index("ix_indicator_type_normalized_value", table_name="indicator")
    op.drop_index("ix_indicator_last_seen", table_name="indicator")
    op.drop_index("ix_indicator_indicator_type", table_name="indicator")
    op.drop_index("ix_indicator_normalized_value", table_name="indicator")
    op.drop_index("ix_indicator_canonical_key", table_name="indicator")
    op.drop_table("indicator")

    op.drop_index("ix_raw_source_record_lookup_fields_gin", table_name="raw_source_record")
    op.drop_index("ix_raw_source_record_batch_source_record", table_name="raw_source_record")
    op.drop_index(op.f("ix_raw_source_record_source_name"), table_name="raw_source_record")
    op.drop_table("raw_source_record")

    op.drop_index(op.f("ix_raw_ingest_batch_source_job_id"), table_name="raw_ingest_batch")
    op.drop_index(op.f("ix_raw_ingest_batch_source_name"), table_name="raw_ingest_batch")
    op.drop_table("raw_ingest_batch")
