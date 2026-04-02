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
)
from mitre.service import (
    DatabaseNotReadyError,
    get_attack_object,
    get_attack_status,
    search_attack_content,
    sync_attack_content,
)
from utils.llm import LLMConfigurationError, LLMRequestError, generate_text


app = FastAPI(title="SoC Fusion Backend")


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
