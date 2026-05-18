from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator


class BaseRequest(BaseModel):
    """
    Base class for API request models to ensure consistent validation behavior.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class BaseResponse(BaseModel):
    """
    Base class for API response models to ensure consistent serialization behavior.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )


class MitreSearchRequest(BaseRequest):
    q: str = Field(..., description="Search text or ATT&CK ID")
    object_type: str | None = Field(
        default=None, description="Filter by MITRE object type"
    )
    domain: str | None = Field(default=None, description="Filter by ATT&CK domain")
    limit: int = Field(default=20, ge=1, le=100)

    @field_validator("q")
    @classmethod
    def validate_query(cls, value: str) -> str:
        if value == "":
            raise ValueError("q cannot be empty")
        return value

    @field_validator("object_type", "domain")
    @classmethod
    def validate_optional_text(
        cls, value: str | None, info: ValidationInfo
    ) -> str | None:
        if value == "":
            raise ValueError(f"{info.field_name} cannot be empty")
        return value


class MitreObjectRequest(BaseRequest):
    stix_id: str = Field(..., description="STIX ID returned by search")

    @field_validator("stix_id")
    @classmethod
    def validate_stix_id(cls, value: str) -> str:
        if value == "":
            raise ValueError("stix_id cannot be empty")
        return value


class LLMGenerateRequest(BaseRequest):
    prompt: str = Field(..., max_length=12000)

    @field_validator("prompt")
    @classmethod
    def validate_prompt(cls, value: str) -> str:
        if value == "":
            raise ValueError("prompt cannot be empty")
        return value


class VirusTotalPulseScanRequest(BaseRequest):
    pulse: str = Field(..., description="Indicator to scan (hash, domain, IP, or URL)")
    indicator_type: str = Field(
        default="auto",
        description="One of: auto, file, domain, ip, url",
    )

    @field_validator("pulse")
    @classmethod
    def validate_pulse(cls, value: str) -> str:
        if value == "":
            raise ValueError("pulse cannot be empty")
        return value

    @field_validator("indicator_type")
    @classmethod
    def validate_indicator_type(cls, value: str) -> str:
        allowed = {"auto", "file", "domain", "ip", "url"}
        normalized = value.lower()
        if normalized not in allowed:
            raise ValueError("indicator_type must be one of: auto, file, domain, ip, url")
        return normalized


class VirusTotalPulseBatchScanRequest(BaseRequest):
    items: list[VirusTotalPulseScanRequest] = Field(..., min_length=1, max_length=100)
    continue_on_error: bool = Field(
        default=True,
        description="Continue scanning remaining items if one item fails",
    )


class OTXIndicatorLookupRequest(BaseRequest):
    indicator: str = Field(..., description="Indicator to look up (hash, domain, IP, or URL)")
    indicator_type: str = Field(
        default="auto",
        description="One of: auto, file, domain, ip, url",
    )

    @field_validator("indicator")
    @classmethod
    def validate_indicator(cls, value: str) -> str:
        if value == "":
            raise ValueError("indicator cannot be empty")
        return value

    @field_validator("indicator_type")
    @classmethod
    def validate_indicator_type(cls, value: str) -> str:
        allowed = {"auto", "file", "domain", "ip", "url"}
        normalized = value.lower()
        if normalized not in allowed:
            raise ValueError("indicator_type must be one of: auto, file, domain, ip, url")
        return normalized


class OTXIndicatorBatchLookupRequest(BaseRequest):
    items: list[OTXIndicatorLookupRequest] = Field(..., min_length=1, max_length=100)
    continue_on_error: bool = Field(
        default=True,
        description="Continue looking up remaining items if one item fails",
    )


class HealthCheckResponse(BaseResponse):
    status: str


class RawCacheEntryResponse(BaseResponse):
    path: str
    size_bytes: int
    modified_at: str


class MitreStatusResponse(BaseResponse):
    database_ready: bool
    database_path: str
    raw_cache: dict[str, RawCacheEntryResponse]
    source_urls: dict[str, str]
    counts: dict[str, int] | None = None
    synced_at: str | None = None
    document_count: int | None = None


class MitreRefreshResponse(BaseResponse):
    status: str
    synced_at: str
    documents_indexed: int
    counts: dict[str, int]


class MitreSearchResultResponse(BaseResponse):
    stix_id: str
    attack_id: str | None = None
    name: str
    object_type: str
    domains: list[str]
    url: str | None = None
    description: str | None = None
    score: int


class MitreSearchResponse(BaseResponse):
    query: str
    object_type: str | None = None
    domain: str | None = None
    count: int
    results: list[MitreSearchResultResponse]


class MitreObjectResponse(BaseResponse):
    model_config = ConfigDict(extra="allow")


class LLMGenerateResponse(BaseResponse):
    provider: str
    model: str
    text: str


class VirusTotalPulseScanResponse(BaseResponse):
    provider: str
    indicator: str
    indicator_type: str
    source: str
    found: bool
    object_id: str | None = None
    object_type: str | None = None
    reputation: int | None = None
    last_analysis_stats: dict[str, int] | None = None
    last_analysis_date: str | None = None
    link: str


class VirusTotalPulseBatchItemResponse(BaseResponse):
    pulse: str
    indicator_type: str
    success: bool
    result: VirusTotalPulseScanResponse | None = None
    error: dict[str, object] | None = None


class VirusTotalPulseBatchScanResponse(BaseResponse):
    total: int
    success_count: int
    failure_count: int
    results: list[VirusTotalPulseBatchItemResponse]
