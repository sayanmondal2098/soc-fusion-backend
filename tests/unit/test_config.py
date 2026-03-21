from __future__ import annotations

import os
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app.core.config import (
    BucketStorageSettings,
    ConfigurationError,
    Environment,
    FileSystemStorageSettings,
    Settings,
    clear_settings_cache,
    validate_startup_settings,
)


class SettingsTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_settings_cache()

    def test_from_env_loads_filesystem_storage_settings(self) -> None:
        settings = Settings.from_env(
            {
                "DATABASE_URL": "postgresql+psycopg://user:pass@db/socfusion",
                "OTX_API_KEY": "otx-key",
                "MISP_URL": "https://misp.example/api",
                "MISP_API_KEY": "misp-key",
                "ADMIN_AUTH_SECRET": "admin-secret",
                "RAW_STORAGE_PATH": "var/raw-intel",
                "APP_ENV": "production",
                "DEBUG": "true",
            }
        )

        self.assertEqual(settings.environment, Environment.PRODUCTION)
        self.assertTrue(settings.debug)
        self.assertIsInstance(settings.storage, FileSystemStorageSettings)
        self.assertEqual(settings.storage.raw_storage_path, Path("var/raw-intel"))

    def test_from_env_loads_bucket_storage_settings(self) -> None:
        settings = Settings.from_env(
            {
                "DATABASE_URL": "postgresql+psycopg://user:pass@db/socfusion",
                "OTX_API_KEY": "otx-key",
                "MISP_URL": "https://misp.example/api",
                "MISP_API_KEY": "misp-key",
                "ADMIN_ROUTE_AUTH_SECRET": "admin-secret",
                "RAW_STORAGE_BUCKET": "soc-fusion-raw",
                "RAW_STORAGE_BUCKET_REGION": "ap-south-1",
                "RAW_STORAGE_BUCKET_PREFIX": "ingest/",
                "RAW_STORAGE_ENDPOINT_URL": "https://s3.example.internal",
            }
        )

        self.assertIsInstance(settings.storage, BucketStorageSettings)
        self.assertEqual(settings.storage.bucket_name, "soc-fusion-raw")
        self.assertEqual(settings.storage.bucket_region, "ap-south-1")
        self.assertEqual(settings.storage.bucket_prefix, "ingest/")
        self.assertEqual(
            settings.storage.endpoint_url,
            "https://s3.example.internal",
        )

    def test_from_env_reads_dotenv_file_and_env_overrides_it(self) -> None:
        scratch_dir = self._make_scratch_dir()
        try:
            dotenv_path = scratch_dir / ".env"
            dotenv_path.write_text(
                "\n".join(
                    [
                        "DATABASE_URL=postgresql+psycopg://dotenv-user:pass@db/socfusion",
                        "OTX_API_KEY=dotenv-otx-key",
                        "MISP_URL=https://dotenv-misp.example/api",
                        "MISP_API_KEY=dotenv-misp-key",
                        "ADMIN_AUTH_SECRET=dotenv-admin-secret",
                        "RAW_STORAGE_PATH=dotenv/raw",
                    ]
                ),
                encoding="utf-8",
            )

            settings = Settings.from_env(
                {
                    "OTX_API_KEY": "runtime-otx-key",
                    "RAW_STORAGE_PATH": "runtime/raw",
                },
                dotenv_path=dotenv_path,
            )
        finally:
            shutil.rmtree(scratch_dir, ignore_errors=True)

        self.assertEqual(
            settings.database_url,
            "postgresql+psycopg://dotenv-user:pass@db/socfusion",
        )
        self.assertEqual(settings.otx_api_key, "runtime-otx-key")
        self.assertEqual(settings.admin_auth_secret, "dotenv-admin-secret")
        self.assertEqual(settings.storage.raw_storage_path, Path("runtime/raw"))

    def test_missing_required_secrets_raise_configuration_error(self) -> None:
        with self.assertRaises(ConfigurationError) as context:
            Settings.from_env({})

        self.assertEqual(
            set(context.exception.missing),
            {
                "ADMIN_AUTH_SECRET",
                "DATABASE_URL",
                "MISP_API_KEY",
                "MISP_URL",
                "OTX_API_KEY",
                "RAW_STORAGE_PATH or RAW_STORAGE_BUCKET",
            },
        )

    def test_invalid_urls_and_bool_raise_configuration_error(self) -> None:
        with self.assertRaises(ConfigurationError) as context:
            Settings.from_env(
                {
                    "DATABASE_URL": "postgresql+psycopg://user:pass@db/socfusion",
                    "OTX_API_KEY": "otx-key",
                    "MISP_URL": "not-a-url",
                    "MISP_API_KEY": "misp-key",
                    "ADMIN_AUTH_SECRET": "admin-secret",
                    "RAW_STORAGE_BUCKET": "soc-fusion-raw",
                    "RAW_STORAGE_ENDPOINT_URL": "ftp://bad-endpoint",
                    "DEBUG": "sometimes",
                }
            )

        self.assertEqual(
            context.exception.invalid,
            {
                "DEBUG": "must be a boolean value",
                "MISP_URL": "must be an absolute http(s) URL",
                "RAW_STORAGE_ENDPOINT_URL": "must be an absolute http(s) URL",
            },
        )

    def test_validate_startup_settings_reads_env_file(self) -> None:
        scratch_dir = self._make_scratch_dir()
        try:
            env_file = scratch_dir / "service.env"
            env_file.write_text(
                "\n".join(
                    [
                        "# comment",
                        "export DATABASE_URL=postgresql+psycopg://dotenv-user:pass@db/socfusion",
                        "OTX_API_KEY=dotenv-otx-key",
                        "MISP_URL=https://dotenv-misp.example/api",
                        "MISP_API_KEY=dotenv-misp-key",
                        "ADMIN_AUTH_SECRET=\"dotenv-admin-secret\"",
                        "RAW_STORAGE_BUCKET=soc-fusion-raw",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"ENV_FILE": str(env_file)}, clear=True):
                loaded = validate_startup_settings()
        finally:
            shutil.rmtree(scratch_dir, ignore_errors=True)

        self.assertEqual(loaded.misp_url, "https://dotenv-misp.example/api")
        self.assertEqual(loaded.admin_auth_secret, "dotenv-admin-secret")
        self.assertIsInstance(loaded.storage, BucketStorageSettings)

    def _make_scratch_dir(self) -> Path:
        path = Path("tests") / ".tmp" / uuid4().hex
        path.mkdir(parents=True, exist_ok=False)
        return path


if __name__ == "__main__":
    unittest.main()
