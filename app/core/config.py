"""Environment-backed application settings for backend services."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse


class ConfigurationError(ValueError):
    """Raised when required configuration is missing or invalid."""

    def __init__(
        self,
        *,
        missing: list[str] | None = None,
        invalid: dict[str, str] | None = None,
    ) -> None:
        self.missing = tuple(sorted(missing or ()))
        self.invalid = dict(sorted((invalid or {}).items()))

        problems: list[str] = []
        if self.missing:
            problems.append(
                "Missing required configuration: " + ", ".join(self.missing)
            )
        if self.invalid:
            details = ", ".join(
                f"{name} ({reason})" for name, reason in self.invalid.items()
            )
            problems.append("Invalid configuration: " + details)

        super().__init__(". ".join(problems) or "Invalid configuration.")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class StorageBackend(StrEnum):
    FILESYSTEM = "filesystem"
    BUCKET = "bucket"


@dataclass(slots=True, frozen=True, kw_only=True)
class FileSystemStorageSettings:
    raw_storage_path: Path
    backend: StorageBackend = field(
        default=StorageBackend.FILESYSTEM,
        init=False,
    )


@dataclass(slots=True, frozen=True, kw_only=True)
class BucketStorageSettings:
    bucket_name: str
    bucket_region: str | None = None
    bucket_prefix: str = ""
    endpoint_url: str | None = None
    backend: StorageBackend = field(
        default=StorageBackend.BUCKET,
        init=False,
    )


RawStorageSettings = FileSystemStorageSettings | BucketStorageSettings


@dataclass(slots=True, frozen=True, kw_only=True)
class Settings:
    database_url: str = field(repr=False)
    otx_api_key: str = field(repr=False)
    misp_url: str
    misp_api_key: str = field(repr=False)
    admin_auth_secret: str = field(repr=False)
    storage: RawStorageSettings
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        dotenv_path: str | Path | None = None,
    ) -> "Settings":
        source = _build_settings_source(env=env, dotenv_path=dotenv_path)
        missing: list[str] = []
        invalid: dict[str, str] = {}

        database_url = _read_required(source, "DATABASE_URL", missing)
        otx_api_key = _read_required(source, "OTX_API_KEY", missing)
        misp_url = _read_required(source, "MISP_URL", missing)
        misp_api_key = _read_required(source, "MISP_API_KEY", missing)
        admin_auth_secret = _read_first_required(
            source,
            names=("ADMIN_AUTH_SECRET", "ADMIN_ROUTE_AUTH_SECRET"),
            reported_name="ADMIN_AUTH_SECRET",
            missing=missing,
        )

        if misp_url is not None and not _is_absolute_http_url(misp_url):
            invalid["MISP_URL"] = "must be an absolute http(s) URL"

        environment = _parse_environment(_read_optional(source, "APP_ENV"), invalid)
        debug = _parse_bool(_read_optional(source, "DEBUG"), "DEBUG", invalid)
        storage = _load_storage_settings(source, missing, invalid)

        if missing or invalid:
            raise ConfigurationError(missing=missing, invalid=invalid)

        return cls(
            database_url=database_url,
            otx_api_key=otx_api_key,
            misp_url=misp_url,
            misp_api_key=misp_api_key,
            admin_auth_secret=admin_auth_secret,
            storage=storage,
            environment=environment,
            debug=debug,
        )


def _build_settings_source(
    *,
    env: Mapping[str, str] | None,
    dotenv_path: str | Path | None,
) -> Mapping[str, str]:
    runtime_source = dict(os.environ if env is None else env)
    resolved_dotenv_path = _resolve_dotenv_path(env=env, dotenv_path=dotenv_path)

    if resolved_dotenv_path is None:
        return runtime_source

    dotenv_values = _load_dotenv_values(resolved_dotenv_path)
    if not dotenv_values:
        return runtime_source

    return {**dotenv_values, **runtime_source}


def _resolve_dotenv_path(
    *,
    env: Mapping[str, str] | None,
    dotenv_path: str | Path | None,
) -> Path | None:
    if dotenv_path is not None:
        return Path(dotenv_path).expanduser()

    env_file = None
    if env is None:
        env_file = os.environ.get("ENV_FILE")
    else:
        env_file = env.get("ENV_FILE")

    if env_file:
        return Path(env_file).expanduser()

    if env is None:
        return _default_dotenv_path()

    return None


def _default_dotenv_path() -> Path:
    return Path(__file__).resolve().parents[2] / ".env"


def _load_dotenv_values(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}

    values: dict[str, str] = {}

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(),
        start=1,
    ):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("export "):
            stripped = stripped[7:].lstrip()

        if "=" not in stripped:
            raise ConfigurationError(
                invalid={f"{path.name}:{line_number}": "must use KEY=VALUE syntax"}
            )

        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            raise ConfigurationError(
                invalid={f"{path.name}:{line_number}": "must define a variable name"}
            )

        values[key] = _parse_dotenv_value(
            raw_value.strip(),
            source_name=f"{path.name}:{line_number}",
        )

    return values


def _parse_dotenv_value(raw_value: str, *, source_name: str) -> str:
    if not raw_value:
        return ""

    if raw_value[0] in {'"', "'"}:
        quote = raw_value[0]
        if len(raw_value) < 2 or raw_value[-1] != quote:
            raise ConfigurationError(
                invalid={source_name: "quoted values must close on the same line"}
            )

        return raw_value[1:-1]

    value_without_comment = raw_value.split(" #", 1)[0]
    return value_without_comment.strip()


def _read_optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None:
        return None

    cleaned = value.strip()
    return cleaned or None


def _read_required(env: Mapping[str, str], name: str, missing: list[str]) -> str | None:
    value = _read_optional(env, name)
    if value is None:
        missing.append(name)
    return value


def _read_first_required(
    env: Mapping[str, str],
    *,
    names: tuple[str, ...],
    reported_name: str,
    missing: list[str],
) -> str | None:
    for name in names:
        value = _read_optional(env, name)
        if value is not None:
            return value

    missing.append(reported_name)
    return None


def _parse_environment(value: str | None, invalid: dict[str, str]) -> Environment:
    if value is None:
        return Environment.DEVELOPMENT

    try:
        return Environment(value.lower())
    except ValueError:
        valid_values = ", ".join(item.value for item in Environment)
        invalid["APP_ENV"] = f"must be one of: {valid_values}"
        return Environment.DEVELOPMENT


def _parse_bool(value: str | None, name: str, invalid: dict[str, str]) -> bool:
    if value is None:
        return False

    normalized = value.lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False

    invalid[name] = "must be a boolean value"
    return False


def _is_absolute_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _load_storage_settings(
    env: Mapping[str, str],
    missing: list[str],
    invalid: dict[str, str],
) -> RawStorageSettings | None:
    raw_storage_path = _read_optional(env, "RAW_STORAGE_PATH")
    if raw_storage_path is not None:
        return FileSystemStorageSettings(raw_storage_path=Path(raw_storage_path))

    bucket_name = _read_optional(env, "RAW_STORAGE_BUCKET")
    if bucket_name is not None:
        endpoint_url = _read_optional(env, "RAW_STORAGE_ENDPOINT_URL")
        if endpoint_url is not None and not _is_absolute_http_url(endpoint_url):
            invalid["RAW_STORAGE_ENDPOINT_URL"] = "must be an absolute http(s) URL"

        return BucketStorageSettings(
            bucket_name=bucket_name,
            bucket_region=_read_optional(env, "RAW_STORAGE_BUCKET_REGION"),
            bucket_prefix=_read_optional(env, "RAW_STORAGE_BUCKET_PREFIX") or "",
            endpoint_url=endpoint_url,
        )

    missing.append("RAW_STORAGE_PATH or RAW_STORAGE_BUCKET")
    return None


@lru_cache(maxsize=8)
def get_settings(dotenv_path: str | Path | None = None) -> Settings:
    """Load and cache validated settings from `.env` and process environment variables."""
    return Settings.from_env(dotenv_path=dotenv_path)


def validate_startup_settings(dotenv_path: str | Path | None = None) -> Settings:
    """Fail fast during service startup when critical configuration is missing."""
    return get_settings(dotenv_path=dotenv_path)


def clear_settings_cache() -> None:
    """Reset the cached settings instance, primarily for tests."""
    get_settings.cache_clear()


__all__ = [
    "BucketStorageSettings",
    "ConfigurationError",
    "Environment",
    "FileSystemStorageSettings",
    "RawStorageSettings",
    "Settings",
    "StorageBackend",
    "clear_settings_cache",
    "get_settings",
    "validate_startup_settings",
]
