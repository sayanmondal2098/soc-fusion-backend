from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Any
from datetime import datetime

class AbuseIPDBQuotaHeaders(BaseModel):
    limit: Optional[int] = None
    remaining: Optional[int] = None
    reset_epoch: Optional[int] = None
    retry_after: Optional[int] = None

class AbuseIPDBSingleResponse(BaseModel):
    model_config = ConfigDict(extra='allow')
    data: Any
    quota: Optional[AbuseIPDBQuotaHeaders] = None

class AbuseIPDBBatchRequest(BaseModel):
    ips: List[str]
    max_age_days: int = 90
    verbose: bool = False

class AbuseIPDBReportRequest(BaseModel):
    ip: str
    categories: List[int]
    comment: Optional[str] = None
    timestamp: Optional[datetime] = None

class AbuseIPDBReportResponse(BaseModel):
    status: str
    message: Optional[str] = None
    data: Optional[Any] = None
    quota: Optional[AbuseIPDBQuotaHeaders] = None
