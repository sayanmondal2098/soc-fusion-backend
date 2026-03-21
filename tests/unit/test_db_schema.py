from __future__ import annotations

import unittest

from app.db import Base
from app.db.models import Indicator, RawSourceRecord, SourceCheckpoint


class DatabaseSchemaTests(unittest.TestCase):
    def test_required_tables_are_registered(self) -> None:
        self.assertEqual(
            set(Base.metadata.tables),
            {
                "export_audit",
                "indicator",
                "indicator_source_link",
                "normalization_error",
                "raw_ingest_batch",
                "raw_source_record",
                "source_checkpoint",
            },
        )

    def test_indicator_indexes_match_required_shape(self) -> None:
        index_names = {index.name for index in Indicator.__table__.indexes}

        self.assertTrue(
            {
                "ix_indicator_canonical_key",
                "ix_indicator_normalized_value",
                "ix_indicator_indicator_type",
                "ix_indicator_last_seen",
                "ix_indicator_type_normalized_value",
                "ix_indicator_tags_gin",
                "ix_indicator_lookup_fields_gin",
            }.issubset(index_names)
        )

    def test_gin_indexes_target_postgresql_lookup_fields(self) -> None:
        indicator_indexes = {index.name: index for index in Indicator.__table__.indexes}
        raw_record_indexes = {index.name: index for index in RawSourceRecord.__table__.indexes}
        checkpoint_indexes = {index.name: index for index in SourceCheckpoint.__table__.indexes}

        self.assertEqual(
            indicator_indexes["ix_indicator_tags_gin"].dialect_options["postgresql"]["using"],
            "gin",
        )
        self.assertEqual(
            indicator_indexes["ix_indicator_lookup_fields_gin"].dialect_options["postgresql"]["using"],
            "gin",
        )
        self.assertEqual(
            raw_record_indexes["ix_raw_source_record_lookup_fields_gin"].dialect_options["postgresql"]["using"],
            "gin",
        )
        self.assertEqual(
            checkpoint_indexes["ix_source_checkpoint_cursor_value_gin"].dialect_options["postgresql"]["using"],
            "gin",
        )


if __name__ == "__main__":
    unittest.main()
