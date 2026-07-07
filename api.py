from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from base_request import (
    BaseRequest,
    HealthCheckResponse,
    LLMGenerateRequest,
    LLMGenerateResponse,
    MitreObjectRequest,
    MitreObjectResponse,
    MitreRefreshResponse,
    MitreSearchRequest,
    MitreSearchResponse,
    MitreStatusResponse,
    VirusTotalPulseBatchItemResponse,
    VirusTotalPulseBatchScanRequest,
    VirusTotalPulseBatchScanResponse,
    VirusTotalPulseScanRequest,
    VirusTotalPulseScanResponse,
)
from mitre.service import (
    DatabaseNotReadyError,
    get_attack_object,
    get_attack_status,
    search_attack_content,
    sync_attack_content,
)
from otx.service import OTXRequestError
from utils.llm import LLMConfigurationError, LLMRequestError, generate_text
from virustotal.service import (
    VirusTotalConfigurationError,
    VirusTotalRequestError,
    scan_pulse,
)

app = FastAPI(title="SoC Fusion Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _raise_virustotal_http_error(exc: VirusTotalRequestError) -> None:
    if exc.status_code == 404:
        raise HTTPException(status_code=404, detail=exc.to_dict()) from exc

    status_code = 503 if exc.status_code == 429 else 502
    raise HTTPException(status_code=status_code, detail=exc.to_dict()) from exc


def _raise_otx_http_error(exc: OTXRequestError) -> None:
    if exc.status_code == 404:
        raise HTTPException(status_code=404, detail=exc.to_dict()) from exc

    status_code = 503 if exc.status_code == 429 else 502
    raise HTTPException(status_code=status_code, detail=exc.to_dict()) from exc


@app.get("/health", response_model=HealthCheckResponse)
async def health_check(_request: BaseRequest = Query(...)) -> HealthCheckResponse:
    return HealthCheckResponse(status="ok")


@app.get("/mitre/status", response_model=MitreStatusResponse)
def mitre_status(_request: BaseRequest = Query(...)) -> MitreStatusResponse:
    return MitreStatusResponse.model_validate(get_attack_status())


@app.post("/mitre/refresh", response_model=MitreRefreshResponse)
def mitre_refresh(_request: BaseRequest = Query(...)) -> MitreRefreshResponse:
    try:
        return MitreRefreshResponse.model_validate(sync_attack_content())
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/mitre/search", response_model=MitreSearchResponse)
def mitre_search(request: MitreSearchRequest = Query(...)) -> MitreSearchResponse:
    try:
        return MitreSearchResponse.model_validate(
            search_attack_content(
                query=request.q,
                object_type=request.object_type,
                domain=request.domain,
                limit=request.limit,
            )
        )
    except DatabaseNotReadyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/mitre/object", response_model=MitreObjectResponse)
def mitre_object(request: MitreObjectRequest = Query(...)) -> MitreObjectResponse:
    try:
        document = get_attack_object(request.stix_id)
    except DatabaseNotReadyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if document is None:
        raise HTTPException(
            status_code=404, detail=f"MITRE object not found: {request.stix_id}"
        )

    return MitreObjectResponse.model_validate(document)


@app.post("/llm/generate", response_model=LLMGenerateResponse)
def llm_generate(payload: LLMGenerateRequest) -> LLMGenerateResponse:
    try:
        return LLMGenerateResponse.model_validate(generate_text(payload.prompt))
    except LLMConfigurationError as exc:
        raise HTTPException(status_code=500, detail=exc.to_dict()) from exc
    except LLMRequestError as exc:
        raise HTTPException(status_code=502, detail=exc.to_dict()) from exc


@app.post("/virustotal/scan-pulse", response_model=VirusTotalPulseScanResponse)
def virustotal_scan_pulse(
    payload: VirusTotalPulseScanRequest,
) -> VirusTotalPulseScanResponse:
    try:
        result = scan_pulse(
            indicator=payload.pulse,
            indicator_type=payload.indicator_type,
        )
        return VirusTotalPulseScanResponse.model_validate(result)
    except VirusTotalConfigurationError as exc:
        raise HTTPException(status_code=500, detail=exc.to_dict()) from exc
    except VirusTotalRequestError as exc:
        _raise_virustotal_http_error(exc)


@app.post(
    "/virustotal/scan-pulse/batch", response_model=VirusTotalPulseBatchScanResponse
)
def virustotal_scan_pulse_batch(
    payload: VirusTotalPulseBatchScanRequest,
) -> VirusTotalPulseBatchScanResponse:
    results: list[VirusTotalPulseBatchItemResponse] = []

    for item in payload.items:
        try:
            result = scan_pulse(
                indicator=item.pulse, indicator_type=item.indicator_type
            )
            results.append(
                VirusTotalPulseBatchItemResponse(
                    pulse=item.pulse,
                    indicator_type=item.indicator_type,
                    success=True,
                    result=VirusTotalPulseScanResponse.model_validate(result),
                )
            )
        except VirusTotalConfigurationError as exc:
            error_detail = exc.to_dict()
            if not payload.continue_on_error:
                raise HTTPException(status_code=500, detail=error_detail) from exc

            results.append(
                VirusTotalPulseBatchItemResponse(
                    pulse=item.pulse,
                    indicator_type=item.indicator_type,
                    success=False,
                    error=error_detail,
                )
            )
        except VirusTotalRequestError as exc:
            error_detail = exc.to_dict()
            if not payload.continue_on_error:
                _raise_virustotal_http_error(exc)

            results.append(
                VirusTotalPulseBatchItemResponse(
                    pulse=item.pulse,
                    indicator_type=item.indicator_type,
                    success=False,
                    error=error_detail,
                )
            )

    success_count = sum(1 for item in results if item.success)
    failure_count = len(results) - success_count
    return VirusTotalPulseBatchScanResponse(
        total=len(results),
        success_count=success_count,
        failure_count=failure_count,
        results=results,
    )


# --- AbuseIPDB ---

from abuseipdb.service import AbuseIPDBService
from abuseipdb.exceptions import (
    AbuseIPDBError,
    AbuseIPDBAuthError,
    AbuseIPDBRateLimitError,
    AbuseIPDBValidationError,
    AbuseIPDBPlanLimitError,
    AbuseIPDBProviderError
)
from abuseipdb.schemas import AbuseIPDBBatchRequest, AbuseIPDBReportRequest

def _raise_abuseipdb_http_error(exc: Exception) -> None:
    if isinstance(exc, AbuseIPDBValidationError):
        raise HTTPException(status_code=422, detail=str(exc))
    elif isinstance(exc, AbuseIPDBAuthError):
        raise HTTPException(status_code=502, detail={"code": "provider_auth_failed", "message": str(exc)})
    elif isinstance(exc, AbuseIPDBRateLimitError):
        raise HTTPException(status_code=429, detail={"code": "abuseipdb_rate_limited", "message": str(exc)})
    elif isinstance(exc, AbuseIPDBPlanLimitError):
        raise HTTPException(status_code=402, detail={"code": "provider_plan_limit", "message": str(exc)})
    elif isinstance(exc, AbuseIPDBProviderError):
        raise HTTPException(status_code=503, detail={"code": "provider_unavailable", "message": str(exc)})
    elif isinstance(exc, AbuseIPDBError):
        raise HTTPException(status_code=500, detail={"code": "abuseipdb_error", "message": str(exc)})
    else:
        raise HTTPException(status_code=500, detail={"code": "internal_error", "message": "An unexpected error occurred."})


@app.get("/abuseipdb")
def abuseipdb_get(
    operation: str = Query(..., description="check, reports, blacklist, check-block"),
    ip: str = Query(None),
    network: str = Query(None),
    max_age_days: int = Query(90),
    verbose: bool = Query(False),
    page: int = Query(1),
    per_page: int = Query(100),
    confidence_minimum: int = Query(75),
    limit: int = Query(10000),
    ip_version: int = Query(None)
):
    service = AbuseIPDBService()
    try:
        if operation == "check":
            if not ip: raise HTTPException(400, "ip is required for check")
            return service.check_ip(ip, max_age_days, verbose)
        elif operation == "reports":
            if not ip: raise HTTPException(400, "ip is required for reports")
            return service.get_reports(ip, max_age_days, page, per_page)
        elif operation == "blacklist":
            return service.get_blacklist(confidence_minimum, limit, ip_version)
        elif operation == "check-block":
            if not network: raise HTTPException(400, "network is required for check-block")
            return service.check_block(network, max_age_days)
        else:
            raise HTTPException(400, "Invalid operation")
    except Exception as e:
        _raise_abuseipdb_http_error(e)


@app.post("/abuseipdb")
def abuseipdb_post(
    operation: str = Query(..., description="batch, report"),
    payload: dict = dict()
):
    service = AbuseIPDBService()
    try:
        if operation == "batch":
            req = AbuseIPDBBatchRequest(**payload)
            results = []
            for ip_addr in set(req.ips):
                try:
                    res = service.check_ip(ip_addr, req.max_age_days, req.verbose)
                    results.append({"ip": ip_addr, "status": "success", "data": res.data})
                except AbuseIPDBRateLimitError as e:
                    results.append({"ip": ip_addr, "status": "rate_limited", "error": str(e)})
                    break
                except Exception as e:
                    results.append({"ip": ip_addr, "status": "error", "error": str(e)})
            return {"results": results}
            
        elif operation == "report":
            req = AbuseIPDBReportRequest(**payload)
            return service.report_ip_safely(req.ip, req.categories, req.comment, req.timestamp)
        else:
            raise HTTPException(400, "Invalid operation")
    except Exception as e:
        _raise_abuseipdb_http_error(e)


# --- URLhaus ---

from urlhaus.client import URLhausClient
from urlhaus.schemas import URLhausResponse
from urlhaus.exceptions import (
    URLhausError,
    URLhausAuthError,
    URLhausRateLimitError,
    URLhausValidationError,
    URLhausProviderError,
    URLhausSubmissionDisabledError,
)

def _raise_urlhaus_http_error(exc: Exception) -> None:
    if isinstance(exc, URLhausValidationError):
        raise HTTPException(status_code=422, detail={"code": "validation_error", "message": str(exc)})
    elif isinstance(exc, URLhausAuthError):
        raise HTTPException(status_code=502, detail={"code": "provider_auth_failed", "message": str(exc)})
    elif isinstance(exc, URLhausRateLimitError):
        raise HTTPException(status_code=429, detail={"code": "urlhaus_rate_limited", "message": str(exc)})
    elif isinstance(exc, URLhausSubmissionDisabledError):
        raise HTTPException(status_code=403, detail={"code": "submission_disabled", "message": str(exc)})
    elif isinstance(exc, URLhausProviderError):
        raise HTTPException(status_code=503, detail={"code": "provider_unavailable", "message": str(exc)})
    elif isinstance(exc, URLhausError):
        raise HTTPException(status_code=500, detail={"code": "urlhaus_error", "message": str(exc)})
    else:
        raise HTTPException(status_code=500, detail={"code": "internal_error", "message": "An unexpected error occurred."})


@app.get("/urlhaus", response_model=URLhausResponse)
def urlhaus_get(
    operation: str = Query(..., description="recent_urls, recent_payloads"),
    limit: int = Query(100)
):
    client = URLhausClient()
    try:
        if operation == "recent_urls":
            res = client.get_recent_urls(limit)
            return URLhausResponse(
                success=res.get("query_status") == "ok",
                endpoint="urls/recent",
                query_status=res.get("query_status", "unknown"),
                data=res
            )
        elif operation == "recent_payloads":
            res = client.get_recent_payloads(limit)
            return URLhausResponse(
                success=res.get("query_status") == "ok",
                endpoint="payloads/recent",
                query_status=res.get("query_status", "unknown"),
                data=res
            )
        else:
            raise HTTPException(400, detail={"code": "invalid_operation", "message": "Invalid operation"})
    except Exception as e:
        _raise_urlhaus_http_error(e)


from urlhaus.schemas import URLhausResponse, URLhausQueryRequest

@app.post("/urlhaus", response_model=URLhausResponse)
def urlhaus_post(
    request: URLhausQueryRequest
):
    client = URLhausClient()
    try:
        res = None
        op = request.operation

        if not op:
            if request.url: op = "url"
            elif request.urlid: op = "urlid"
            elif request.host: op = "host"
            elif request.hash: op = "payload"
            elif request.tag: op = "tag"
            elif request.signature: op = "signature"
            elif request.urls: op = "submit"
            else:
                raise HTTPException(400, detail={"code": "missing_operation", "message": "Could not infer operation from payload."})

        if op == "url":
            res = client.query_url(request.url or "")
        elif op == "urlid":
            res = client.query_url_id(request.urlid or "")
        elif op == "host":
            res = client.query_host(request.host or "")
        elif op == "payload":
            res = client.query_payload(request.hash or "")
        elif op == "tag":
            res = client.query_tag(request.tag or "")
        elif op == "signature":
            res = client.query_signature(request.signature or "")
        elif op == "submit":
            res = client.submit_urls(request.urls or [])
        else:
            raise HTTPException(400, detail={"code": "invalid_operation", "message": "Invalid operation"})

        qs = res.get("query_status", "unknown") if isinstance(res, dict) else "unknown"
        success = qs in ("ok", "submitted")
        
        return URLhausResponse(
            success=success,
            endpoint=op,
            query_status=qs,
            data=res
        )
    except Exception as e:
        _raise_urlhaus_http_error(e)

