from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any


VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"
INDICATOR_TYPES = {"file", "domain", "ip", "url"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+\.?$", re.IGNORECASE)
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


class VirusTotalConfigurationError(RuntimeError):
    """Raised when VirusTotal configuration is missing or invalid."""

    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.field = field

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": "virustotal_configuration_error",
            "message": self.message,
        }
        if self.field:
            payload["field"] = self.field
        return payload


class VirusTotalRequestError(RuntimeError):
    """Raised when the VirusTotal API request fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        endpoint: str | None = None,
        retryable: bool | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.endpoint = endpoint
        self.retryable = retryable
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": "virustotal_request_error",
            "message": self.message,
        }
        if self.status_code is not None:
            payload["status_code"] = self.status_code
        if self.endpoint:
            payload["endpoint"] = self.endpoint
        if self.retryable is not None:
            payload["retryable"] = self.retryable
        if self.details:
            payload["details"] = self.details
        return payload


def _get_api_key() -> str:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        raise VirusTotalConfigurationError(
            "VIRUSTOTAL_API_KEY is not configured",
            field="VIRUSTOTAL_API_KEY",
        )

    return api_key


def _is_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(value.strip().lower()))


def _is_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(value.strip())
    return bool(parsed.scheme and parsed.netloc)


def detect_indicator_type(indicator: str) -> str:
    candidate = indicator.strip()

    if HASH_RE.match(candidate):
        return "file"

    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass

    if _is_url(candidate):
        return "url"

    if _is_domain(candidate):
        return "domain"

    raise VirusTotalConfigurationError(
        "Unable to auto-detect indicator type. Provide indicator_type explicitly.",
        field="indicator_type",
    )


def _url_to_id(value: str) -> str:
    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")


def _build_object_path(indicator: str, indicator_type: str) -> str:
    if indicator_type == "file":
        return f"/files/{urllib.parse.quote(indicator, safe='')}"
    if indicator_type == "domain":
        return f"/domains/{urllib.parse.quote(indicator, safe='')}"
    if indicator_type == "ip":
        return f"/ip_addresses/{urllib.parse.quote(indicator, safe='')}"
    if indicator_type == "url":
        return f"/urls/{urllib.parse.quote(_url_to_id(indicator), safe='')}"

    raise VirusTotalConfigurationError(
        f"Unsupported indicator type: {indicator_type}",
        field="indicator_type",
    )


def _to_iso(unix_seconds: int | None) -> str | None:
    if unix_seconds is None:
        return None

    return (
        datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )


def _json_get(path: str, *, api_key: str) -> dict[str, Any]:
    url = f"{VIRUSTOTAL_API_BASE}{path}"
    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "soc-fusion-backend-virustotal/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        retryable = exc.code >= 500 or exc.code == 429
        raise VirusTotalRequestError(
            f"VirusTotal returned HTTP {exc.code}",
            status_code=exc.code,
            endpoint=url,
            retryable=retryable,
            details={"body": detail},
        ) from exc
    except urllib.error.URLError as exc:
        raise VirusTotalRequestError(
            f"VirusTotal request failed: {exc}",
            endpoint=url,
            retryable=True,
        ) from exc
    except json.JSONDecodeError as exc:
        raise VirusTotalRequestError(
            "VirusTotal returned invalid JSON",
            endpoint=url,
            retryable=False,
        ) from exc


def scan_pulse(indicator: str, indicator_type: str = "auto") -> dict[str, Any]:
    resolved_indicator = indicator.strip()
    if not resolved_indicator:
        raise VirusTotalConfigurationError("indicator cannot be empty", field="indicator")

    normalized_type = indicator_type.strip().lower()
    if normalized_type == "auto":
        normalized_type = detect_indicator_type(resolved_indicator)

    if normalized_type not in INDICATOR_TYPES:
        raise VirusTotalConfigurationError(
            "indicator_type must be one of: auto, file, domain, ip, url",
            field="indicator_type",
        )

    api_key = _get_api_key()
    object_path = _build_object_path(resolved_indicator, normalized_type)
    payload = _json_get(object_path, api_key=api_key)

    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}

    return {
        "provider": "virustotal",
        "indicator": resolved_indicator,
        "indicator_type": normalized_type,
        "source": object_path,
        "found": bool(data),
        "object_id": data.get("id"),
        "object_type": data.get("type"),
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "last_analysis_date": _to_iso(attributes.get("last_analysis_date")),
        "link": attributes.get("permalink") or f"https://www.virustotal.com/gui/search/{urllib.parse.quote(resolved_indicator, safe='')}",
    }
