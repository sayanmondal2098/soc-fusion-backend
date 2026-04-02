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
