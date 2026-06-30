from typing import Any, Dict, Tuple, Optional, List
import httpx
from datetime import datetime
import ipaddress

from .exceptions import (
    AbuseIPDBError,
    AbuseIPDBAuthError,
    AbuseIPDBRateLimitError,
    AbuseIPDBValidationError,
    AbuseIPDBPlanLimitError,
    AbuseIPDBProviderError,
)
from .schemas import AbuseIPDBQuotaHeaders

class AbuseIPDBClient:
    def __init__(self, api_key: str, base_url: str, timeout_seconds: int = 20):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds

    def _extract_quota_headers(self, headers: httpx.Headers) -> AbuseIPDBQuotaHeaders:
        return AbuseIPDBQuotaHeaders(
            limit=int(headers.get("X-RateLimit-Limit")) if headers.get("X-RateLimit-Limit") else None,
            remaining=int(headers.get("X-RateLimit-Remaining")) if headers.get("X-RateLimit-Remaining") else None,
            reset_epoch=int(headers.get("X-RateLimit-Reset")) if headers.get("X-RateLimit-Reset") else None,
            retry_after=int(headers.get("Retry-After")) if headers.get("Retry-After") else None,
        )

    def _request(
        self, method: str, endpoint: str, params: Optional[Dict] = None, data: Optional[Dict] = None, files: Optional[Dict] = None
    ) -> Tuple[Dict[str, Any], AbuseIPDBQuotaHeaders]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }

        with httpx.Client(timeout=self.timeout) as client:
            try:
                response = client.request(method, url, headers=headers, params=params, data=data, files=files)
            except httpx.RequestError as e:
                raise AbuseIPDBProviderError(f"Request failed: {str(e)}") from e

        quota = self._extract_quota_headers(response.headers)

        if response.status_code in (400, 422):
            raise AbuseIPDBValidationError(f"Validation error: {response.text}")
        elif response.status_code in (401, 403):
            raise AbuseIPDBAuthError("Authentication or authorization failed.")
        elif response.status_code == 402:
            raise AbuseIPDBPlanLimitError("Plan limit exceeded or endpoint not included in plan.")
        elif response.status_code == 429:
            raise AbuseIPDBRateLimitError("Rate limit exceeded.")
        elif response.status_code >= 500:
            raise AbuseIPDBProviderError(f"Provider error: {response.status_code}")
        
        response.raise_for_status()
        
        return response.json(), quota

    def _validate_ip(self, ip_address: str) -> None:
        try:
            ip = ipaddress.ip_address(ip_address)
            if not ip.is_global:
                raise AbuseIPDBValidationError(f"IP {ip_address} is private, loopback, or reserved.")
        except ValueError:
            raise AbuseIPDBValidationError(f"Invalid IP address format: {ip_address}")

    def check_ip(self, ip_address: str, max_age_days: int = 90, verbose: bool = False) -> Tuple[Dict[str, Any], AbuseIPDBQuotaHeaders]:
        self._validate_ip(ip_address)
        if not 1 <= max_age_days <= 365:
            raise AbuseIPDBValidationError("maxAgeInDays must be between 1 and 365.")

        params = {"ipAddress": ip_address, "maxAgeInDays": max_age_days}
        if verbose:
            params["verbose"] = "true"

        return self._request("GET", "/check", params=params)

    def get_reports(self, ip_address: str, max_age_days: int = 90, page: int = 1, per_page: int = 100) -> Tuple[Dict[str, Any], AbuseIPDBQuotaHeaders]:
        self._validate_ip(ip_address)
        if not 1 <= max_age_days <= 365:
            raise AbuseIPDBValidationError("maxAgeInDays must be between 1 and 365.")
        if not 1 <= per_page <= 100:
            raise AbuseIPDBValidationError("per_page must be between 1 and 100.")

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "page": page,
            "perPage": per_page
        }
        return self._request("GET", "/reports", params=params)

    def get_blacklist(self, confidence_minimum: int = 75, limit: int = 10000, ip_version: Optional[int] = None) -> Tuple[Dict[str, Any], AbuseIPDBQuotaHeaders]:
        if not 25 <= confidence_minimum <= 100:
            raise AbuseIPDBValidationError("confidence_minimum must be between 25 and 100.")
        if limit <= 0:
            raise AbuseIPDBValidationError("limit must be positive.")
        if ip_version not in (None, 4, 6):
            raise AbuseIPDBValidationError("ip_version must be 4, 6, or None.")

        params = {"confidenceMinimum": confidence_minimum, "limit": limit}
        if ip_version:
            params["ipVersion"] = ip_version

        return self._request("GET", "/blacklist", params=params)

    def check_block(self, network: str, max_age_days: int = 30) -> Tuple[Dict[str, Any], AbuseIPDBQuotaHeaders]:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            raise AbuseIPDBValidationError(f"Invalid network CIDR format: {network}")
        
        if not 1 <= max_age_days <= 365:
            raise AbuseIPDBValidationError("maxAgeInDays must be between 1 and 365.")

        params = {"network": network, "maxAgeInDays": max_age_days}
        return self._request("GET", "/check-block", params=params)

    def report_ip(self, ip_address: str, categories: List[int], comment: Optional[str] = None, timestamp: Optional[datetime] = None) -> Tuple[Dict[str, Any], AbuseIPDBQuotaHeaders]:
        self._validate_ip(ip_address)
        data = {
            "ip": ip_address,
            "categories": ",".join(map(str, categories)),
        }
        if comment:
            data["comment"] = comment
        if timestamp:
            data["timestamp"] = timestamp.isoformat()

        return self._request("POST", "/report", data=data)

    def clear_address(self, ip_address: str) -> Tuple[Dict[str, Any], AbuseIPDBQuotaHeaders]:
        params = {"ipAddress": ip_address}
        return self._request("DELETE", "/clear-address", params=params)
