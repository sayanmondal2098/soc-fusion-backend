from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any


OTX_API_BASE = "https://otx.alienvault.com/api/v1"
INDICATOR_TYPES = {"file", "domain", "ip", "url"}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+\.?$",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


class OTXConfigurationError(RuntimeError):
    """Raised when AlienVault OTX configuration is missing or invalid."""

    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.field = field

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": "otx_configuration_error",
            "message": self.message,
        }
        if self.field:
            payload["field"] = self.field
        return payload


class OTXRequestError(RuntimeError):
    """Raised when the AlienVault OTX API request fails."""

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
            "type": "otx_request_error",
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
    api_key = os.getenv("OTX_API_KEY", "").strip()
    if not api_key:
        raise OTXConfigurationError(
            "OTX_API_KEY is not configured",
            field="OTX_API_KEY",
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

    raise OTXConfigurationError(
        "Unable to auto-detect indicator type. Provide indicator_type explicitly.",
        field="indicator_type",
    )


def _to_otx_indicator_type(indicator: str, indicator_type: str) -> str:
    if indicator_type == "domain":
        return "domain"
    if indicator_type == "url":
        return "URL"
    if indicator_type == "ip":
        version = ipaddress.ip_address(indicator).version
        return "IPv4" if version == 4 else "IPv6"
    if indicator_type == "file":
        hash_length_map = {
            32: "FileHash-MD5",
            40: "FileHash-SHA1",
            64: "FileHash-SHA256",
        }
        otx_type = hash_length_map.get(len(indicator))
        if otx_type:
            return otx_type

    raise OTXConfigurationError(
        f"Unsupported indicator type: {indicator_type}",
        field="indicator_type",
    )


def _indicator_path_value(indicator: str, indicator_type: str) -> str:
    if indicator_type == "url":
        return urllib.parse.quote(indicator, safe="")
    return urllib.parse.quote(indicator, safe="")


def _json_get(path: str, *, api_key: str) -> dict[str, Any]:
    url = f"{OTX_API_BASE}{path}"
    request = urllib.request.Request(
        url,
        headers={
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json",
            "User-Agent": "soc-fusion-backend-otx/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        retryable = exc.code >= 500 or exc.code == 429
        raise OTXRequestError(
            f"AlienVault OTX returned HTTP {exc.code}",
            status_code=exc.code,
            endpoint=url,
            retryable=retryable,
            details={"body": detail},
        ) from exc
    except urllib.error.URLError as exc:
        raise OTXRequestError(
            f"AlienVault OTX request failed: {exc}",
            endpoint=url,
            retryable=True,
        ) from exc
    except json.JSONDecodeError as exc:
        raise OTXRequestError(
            "AlienVault OTX returned invalid JSON",
            endpoint=url,
            retryable=False,
        ) from exc


def _get_indicator_details(
    *,
    api_key: str,
    otx_type: str,
    path_indicator: str,
    sections: list[str],
    general_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    details: dict[str, Any] = {}
    detail_errors: dict[str, Any] = {}

    for section in dict.fromkeys(["general", *sections]):
        if section == "general":
            details[section] = general_payload
            continue

        section_path = f"/indicators/{otx_type}/{path_indicator}/{section}"
        try:
            details[section] = _json_get(section_path, api_key=api_key)
        except OTXRequestError as exc:
            detail_errors[section] = exc.to_dict()

    return details, detail_errors


def _to_iso(value: str | int | None) -> str | None:
    if value is None:
        return None

    if isinstance(value, int):
        return (
            datetime.fromtimestamp(value, tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )

    return value


def _pulse_summary(pulse: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": pulse.get("id"),
        "name": pulse.get("name"),
        "author_name": pulse.get("author_name"),
        "created": _to_iso(pulse.get("created")),
        "modified": _to_iso(pulse.get("modified")),
        "tlp": pulse.get("TLP"),
        "tags": pulse.get("tags") or [],
        "references": pulse.get("references") or [],
    }


def _otx_gui_indicator(indicator: str) -> str:
    return urllib.parse.quote(indicator, safe="")


def _stable_object_id(indicator: str, indicator_type: str) -> str:
    digest = hashlib.sha256(f"{indicator_type}:{indicator}".encode("utf-8")).hexdigest()
    return f"otx:{digest}"


def lookup_indicator(indicator: str, indicator_type: str = "auto") -> dict[str, Any]:
    resolved_indicator = indicator.strip()
    if not resolved_indicator:
        raise OTXConfigurationError("indicator cannot be empty", field="indicator")

    normalized_type = indicator_type.strip().lower()
    if normalized_type == "auto":
        normalized_type = detect_indicator_type(resolved_indicator)

    if normalized_type not in INDICATOR_TYPES:
        raise OTXConfigurationError(
            "indicator_type must be one of: auto, file, domain, ip, url",
            field="indicator_type",
        )

    otx_type = _to_otx_indicator_type(resolved_indicator, normalized_type)
    path_indicator = _indicator_path_value(resolved_indicator, normalized_type)
    object_path = f"/indicators/{otx_type}/{path_indicator}/general"
    api_key = _get_api_key()
    payload = _json_get(object_path, api_key=api_key)

    pulse_info = payload.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    pulse_count = int(pulse_info.get("count") or len(pulses))
    sections = payload.get("sections") or []
    details, detail_errors = _get_indicator_details(
        api_key=api_key,
        otx_type=otx_type,
        path_indicator=path_indicator,
        sections=sections,
        general_payload=payload,
    )

    return {
        "provider": "alienvault_otx",
        "indicator": resolved_indicator,
        "indicator_type": normalized_type,
        "otx_indicator_type": otx_type,
        "source": object_path,
        "found": pulse_count > 0,
        "object_id": payload.get("id")
        or _stable_object_id(resolved_indicator, normalized_type),
        "pulse_count": pulse_count,
        "reputation": payload.get("reputation"),
        "sections": sections,
        "validation": payload.get("validation") or [],
        "pulses": [_pulse_summary(pulse) for pulse in pulses[:10]],
        "details": details,
        "detail_errors": detail_errors,
        "link": f"https://otx.alienvault.com/indicator/{otx_type}/{_otx_gui_indicator(resolved_indicator)}",
    }
