from pydantic import BaseModel, ConfigDict
from typing import Optional, Any

class URLhausResponse(BaseModel):
    model_config = ConfigDict(extra='allow')
    success: bool
    endpoint: str
    query_status: str
    data: Optional[Any] = None
    errors: Optional[str] = None

class URLhausQueryRequest(BaseModel):
    operation: Optional[str] = None
    url: Optional[str] = None
    urlid: Optional[str] = None
    host: Optional[str] = None
    hash: Optional[str] = None
    tag: Optional[str] = None
    signature: Optional[str] = None
    urls: Optional[list[dict]] = None

