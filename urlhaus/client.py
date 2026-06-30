import httpx
from typing import Any, Dict, Optional, List

from .config import (
    URLHAUS_AUTH_KEY,
    URLHAUS_BASE_URL,
    URLHAUS_TIMEOUT_SECONDS,
    URLHAUS_ENABLE_SUBMISSION
)
from .exceptions import (
    URLhausAuthError,
    URLhausRateLimitError,
    URLhausProviderError,
    URLhausSubmissionDisabledError,
)
from .validators import (
    validate_url,
    validate_url_id,
    validate_host,
    validate_payload_hash,
    validate_tag_or_signature,
    URLhausUnsafeInputError
)

class URLhausClient:
    def __init__(self):
        self.api_key = URLHAUS_AUTH_KEY
        self.base_url = URLHAUS_BASE_URL.rstrip("/")
        self.timeout = URLHAUS_TIMEOUT_SECONDS

    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        if not self.api_key:
            raise URLhausAuthError("URLhaus Auth-Key is missing in configuration. Check your .env file for URLHAUS_AUTH_KEY.")
            
        headers = {
            "Auth-Key": self.api_key
        }

        with httpx.Client(timeout=self.timeout) as client:
            try:
                # URLhaus mostly uses form-encoded POST requests for querying data
                if method == "POST":
                    response = client.post(url, headers=headers, data=data)
                elif method == "GET":
                    response = client.get(url, headers=headers)
                else:
                    raise URLhausProviderError(f"Unsupported HTTP method: {method}")
            except httpx.RequestError as e:
                raise URLhausProviderError(f"Request failed: {str(e)}") from e

        if response.status_code in (401, 403):
            raise URLhausAuthError(f"Authentication failed: {response.status_code}")
        elif response.status_code == 429:
            raise URLhausRateLimitError("Rate limit exceeded.")
        elif response.status_code >= 500:
            raise URLhausProviderError(f"Provider error: {response.status_code}")
        
        # 400 or 422 could happen if we send bad parameters, but URLhaus typically 
        # returns 200 OK with query_status="invalid_url" or similar inside JSON.
        response.raise_for_status()

        try:
            return response.json()
        except ValueError:
            raise URLhausProviderError("Invalid JSON response from provider.")

    def get_recent_urls(self, limit: int = 100) -> Dict[str, Any]:
        if not (1 <= limit <= 1000):
            raise URLhausUnsafeInputError("Limit must be between 1 and 1000.")
        # Uses GET for recent URLs
        return self._request("GET", "/urls/recent/")

    def query_url(self, url: str) -> Dict[str, Any]:
        validate_url(url)
        return self._request("POST", "/url/", data={"url": url})

    def query_url_id(self, url_id: str | int) -> Dict[str, Any]:
        validate_url_id(url_id)
        return self._request("POST", "/urlid/", data={"urlid": str(url_id)})

    def query_host(self, host: str) -> Dict[str, Any]:
        validate_host(host)
        return self._request("POST", "/host/", data={"host": host})

    def get_recent_payloads(self, limit: int = 100) -> Dict[str, Any]:
        if not (1 <= limit <= 1000):
            raise URLhausUnsafeInputError("Limit must be between 1 and 1000.")
        return self._request("GET", "/payloads/recent/")

    def query_payload(self, hash_value: str) -> Dict[str, Any]:
        hash_type = validate_payload_hash(hash_value)
        return self._request("POST", "/payload/", data={hash_type: hash_value})

    def query_tag(self, tag: str) -> Dict[str, Any]:
        validate_tag_or_signature(tag, "Tag")
        return self._request("POST", "/tag/", data={"tag": tag})

    def query_signature(self, signature: str) -> Dict[str, Any]:
        validate_tag_or_signature(signature, "Signature")
        return self._request("POST", "/signature/", data={"signature": signature})

    def submit_urls(self, urls: List[Dict[str, str]]) -> Dict[str, Any]:
        if not URLHAUS_ENABLE_SUBMISSION:
            raise URLhausSubmissionDisabledError("Submission to URLhaus is disabled by configuration.")
        
        # We perform validation on each URL
        for entry in urls:
            url = entry.get("url")
            validate_url(url)
            
            # Optionally validate tags
            tags = entry.get("tags", [])
            for tag in tags:
                validate_tag_or_signature(tag, "Tag")

        # Create a CSV or JSON payload per URLhaus submission API format
        # However, URLhaus uses a specific submission API format, usually JSON array.
        # But this is disabled by default anyway.
        return self._request("POST", "/submit/", data={"json": urls})
