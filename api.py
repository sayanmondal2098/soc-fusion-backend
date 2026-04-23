from fastapi import FastAPI, HTTPException, Query

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
from utils.llm import LLMConfigurationError, LLMRequestError, generate_text
from virustotal.service import (
    VirusTotalConfigurationError,
    VirusTotalRequestError,
    scan_pulse,
)


app = FastAPI(title="SoC Fusion Backend")


def _raise_virustotal_http_error(exc: VirusTotalRequestError) -> None:
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


@app.post("/virustotal/scan-pulse/batch", response_model=VirusTotalPulseBatchScanResponse)
def virustotal_scan_pulse_batch(
    payload: VirusTotalPulseBatchScanRequest,
) -> VirusTotalPulseBatchScanResponse:
    results: list[VirusTotalPulseBatchItemResponse] = []

    for item in payload.items:
        try:
            result = scan_pulse(indicator=item.pulse, indicator_type=item.indicator_type)
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
