from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


OTX_API_BASE = "https://otx.alienvault.com/api/v1"
OTX_WEB_BASE = "https://otx.alienvault.com/indicator"
INDICATOR_TYPES = {"ip", "domain", "hostname", "url", "file"}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+\.?$",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")

_OTX_TYPE_MAP = {
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "file": "file",
}


class OTXConfigurationError(RuntimeError):
    """Raised when OTX configuration is missing or invalid."""

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
    """Raised when the OTX API request fails."""

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
    """Auto-detect the indicator type from its value."""
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


def _resolve_otx_type(indicator: str, indicator_type: str) -> str:
    """Map logical indicator_type to the OTX URL path segment."""
    if indicator_type == "ip":
        try:
            addr = ipaddress.ip_address(indicator.strip())
            return "IPv6" if addr.version == 6 else "IPv4"
        except ValueError:
            return "IPv4"
    return _OTX_TYPE_MAP[indicator_type]


def _build_api_path(indicator: str, otx_type: str) -> str:
    encoded = urllib.parse.quote(indicator.strip(), safe="")
    return f"/indicators/{otx_type}/{encoded}/general"


def _json_get(path: str, *, api_key: str) -> dict[str, Any]:
    url = f"{OTX_API_BASE}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json",
            "User-Agent": "soc-fusion-backend-otx/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        retryable = exc.code >= 500 or exc.code == 429
        raise OTXRequestError(
            f"OTX returned HTTP {exc.code}",
            status_code=exc.code,
            endpoint=url,
            retryable=retryable,
            details={"body": detail},
        ) from exc
    except urllib.error.URLError as exc:
        raise OTXRequestError(
            f"OTX request failed: {exc}",
            endpoint=url,
            retryable=True,
        ) from exc
    except json.JSONDecodeError as exc:
        raise OTXRequestError(
            "OTX returned invalid JSON",
            endpoint=url,
            retryable=False,
        ) from exc


def _extract_malware_families(pulse_info: dict[str, Any]) -> list[str]:
    families: set[str] = set()
    for pulse in pulse_info.get("pulses", []):
        for mf in pulse.get("malware_families", []):
            name = mf.get("display_name") or mf.get("id", "")
            if name:
                families.add(name)
    return sorted(families)


def _extract_attack_ids(pulse_info: dict[str, Any]) -> list[str]:
    ids: set[str] = set()
    for pulse in pulse_info.get("pulses", []):
        for at in pulse.get("attack_ids", []):
            attack_id = at.get("display_name") or at.get("id", "")
            if attack_id:
                ids.add(attack_id)
    return sorted(ids)


def _extract_industries(pulse_info: dict[str, Any]) -> list[str]:
    industries: set[str] = set()
    for pulse in pulse_info.get("pulses", []):
        for ind in pulse.get("industries", []):
            if isinstance(ind, str) and ind:
                industries.add(ind)
            elif isinstance(ind, dict):
                name = ind.get("name", "")
                if name:
                    industries.add(name)
    return sorted(industries)


def scan_indicator(indicator: str, indicator_type: str = "auto") -> dict[str, Any]:
    """Query AlienVault OTX for a single threat indicator.

    Returns a normalised dict suitable for OTXScanResponse validation.
    """
    resolved_indicator = indicator.strip()
    if not resolved_indicator:
        raise OTXConfigurationError("indicator cannot be empty", field="indicator")

    normalized_type = indicator_type.strip().lower()
    if normalized_type == "auto":
        normalized_type = detect_indicator_type(resolved_indicator)

    if normalized_type not in INDICATOR_TYPES:
        raise OTXConfigurationError(
            "indicator_type must be one of: auto, ip, domain, hostname, url, file",
            field="indicator_type",
        )

    api_key = _get_api_key()
    otx_type = _resolve_otx_type(resolved_indicator, normalized_type)
    api_path = _build_api_path(resolved_indicator, otx_type)
    payload = _json_get(api_path, api_key=api_key)

    pulse_info: dict[str, Any] = payload.get("pulse_info") or {}
    pulse_count: int = pulse_info.get("count", 0)
    reputation: int | None = payload.get("reputation")
    adversary: str | None = payload.get("adversary") or None
    country_codes: list[str] = [c for c in (payload.get("country_code") or []) if c]

    web_link = (
        f"{OTX_WEB_BASE}/{otx_type.lower()}/"
        f"{urllib.parse.quote(resolved_indicator, safe='')}"
    )

    return {
        "provider": "alienvault_otx",
        "indicator": resolved_indicator,
        "indicator_type": normalized_type,
        "source": api_path,
        "found": pulse_count > 0,
        "pulse_count": pulse_count,
        "reputation": reputation,
        "malware_families": _extract_malware_families(pulse_info),
        "adversary": adversary,
        "targeted_countries": country_codes,
        "industries": _extract_industries(pulse_info),
        "attack_ids": _extract_attack_ids(pulse_info),
        "link": web_link,
    }
