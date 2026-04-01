from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from utils.llm import (
    LLMConfigurationError,
    LLMRequestError,
    generate_text,
    get_llm_settings,
)

from mitre.service import (
    DatabaseNotReadyError,
    get_attack_object,
    get_attack_status,
    search_attack_content,
    sync_attack_content,
)


app = FastAPI(title="SoC Fusion Backend")


class LLMGenerateRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=12000)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/mitre/status")
def mitre_status() -> dict:
    return get_attack_status()


@app.post("/mitre/refresh")
def mitre_refresh() -> dict:
    try:
        return sync_attack_content()
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/mitre/search")
def mitre_search(
    q: str = Query(..., min_length=1, description="Search text or ATT&CK ID"),
    object_type: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict:
    try:
        return search_attack_content(
            query=q,
            object_type=object_type,
            domain=domain,
            limit=limit,
        )
    except DatabaseNotReadyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/mitre/object")
def mitre_object(
    stix_id: str = Query(..., min_length=1, description="STIX ID returned by search"),
) -> dict:
    try:
        document = get_attack_object(stix_id)
    except DatabaseNotReadyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if document is None:
        raise HTTPException(
            status_code=404, detail=f"MITRE object not found: {stix_id}"
        )

    return document


@app.post("/llm/generate")
def llm_generate(payload: LLMGenerateRequest) -> dict[str, str]:
    try:
        return generate_text(payload.prompt)
    except LLMConfigurationError as exc:
        raise HTTPException(status_code=500, detail=exc.to_dict()) from exc
    except LLMRequestError as exc:
        raise HTTPException(status_code=502, detail=exc.to_dict()) from exc


@app.get("/llm/settings")
def llm_settings() -> dict:
    return get_llm_settings()
