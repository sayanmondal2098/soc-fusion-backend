import re
from datetime import datetime
from typing import List, Optional

from .config import (
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_BASE_URL,
    ABUSEIPDB_TIMEOUT_SECONDS,
    ABUSEIPDB_ENABLE_EXTERNAL_REPORTING
)
from .client import AbuseIPDBClient
from .schemas import AbuseIPDBSingleResponse, AbuseIPDBReportResponse

class AbuseIPDBService:
    def __init__(self):
        self.client = AbuseIPDBClient(
            api_key=ABUSEIPDB_API_KEY,
            base_url=ABUSEIPDB_BASE_URL,
            timeout_seconds=ABUSEIPDB_TIMEOUT_SECONDS,
        )

    def check_ip(self, ip_address: str, max_age_days: int = 90, verbose: bool = False) -> AbuseIPDBSingleResponse:
        response_json, quota = self.client.check_ip(ip_address, max_age_days, verbose)
        return AbuseIPDBSingleResponse(data=response_json.get("data"), quota=quota)
        
    def check_block(self, network: str, max_age_days: int = 30) -> AbuseIPDBSingleResponse:
        response_json, quota = self.client.check_block(network, max_age_days)
        return AbuseIPDBSingleResponse(data=response_json.get("data"), quota=quota)
        
    def get_blacklist(self, confidence_minimum: int = 75, limit: int = 10000, ip_version: Optional[int] = None) -> AbuseIPDBSingleResponse:
        response_json, quota = self.client.get_blacklist(confidence_minimum, limit, ip_version)
        return AbuseIPDBSingleResponse(data={"meta": response_json.get("meta"), "records": response_json.get("data")}, quota=quota)

    def get_reports(self, ip_address: str, max_age_days: int = 90, page: int = 1, per_page: int = 100) -> AbuseIPDBSingleResponse:
        response_json, quota = self.client.get_reports(ip_address, max_age_days, page, per_page)
        return AbuseIPDBSingleResponse(data=response_json.get("data"), quota=quota)

    def report_ip_safely(self, ip_address: str, categories: List[int], comment: Optional[str] = None, timestamp: Optional[datetime] = None) -> AbuseIPDBReportResponse:
        if not ABUSEIPDB_ENABLE_EXTERNAL_REPORTING:
            return AbuseIPDBReportResponse(
                status="skipped",
                message="External reporting is disabled via config."
            )

        sanitized_comment = comment
        if sanitized_comment:
            # Strip emails
            sanitized_comment = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[EMAIL REMOVED]', sanitized_comment)
            # Strip private IPs
            sanitized_comment = re.sub(r'\b(?:10|127|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b', '[PRIVATE IP REMOVED]', sanitized_comment)

        response_json, quota = self.client.report_ip(ip_address, categories, sanitized_comment, timestamp)
        
        return AbuseIPDBReportResponse(
            status="submitted",
            data=response_json.get("data"),
            quota=quota
        )
