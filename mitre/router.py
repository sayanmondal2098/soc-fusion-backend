from fastapi import APIRouter, HTTPException, Query

from mitre.service import (
    DatabaseNotReadyError,
    get_attack_object,
    get_attack_status,
    search_attack_content,
    sync_attack_content,
)


router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/status")
def mitre_status() -> dict:
    return get_attack_status()


@router.post("/refresh")
def mitre_refresh() -> dict:
    try:
        return sync_attack_content()
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/search")
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


@router.get("/object")
def mitre_object(
    stix_id: str = Query(..., min_length=1, description="STIX ID returned by search"),
) -> dict:
    try:
        document = get_attack_object(stix_id)
    except DatabaseNotReadyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if document is None:
        raise HTTPException(status_code=404, detail=f"MITRE object not found: {stix_id}")

    return document

