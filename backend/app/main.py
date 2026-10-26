from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.log_analyzer import analyze_log
from app.services.incident_store import (
    get_incident,
    list_incidents,
    save_incident,
    update_verification,
    update_fix_description,
)

app = FastAPI(
    title="AI DevOps Incident Assistant",
    description="Local-first DevOps incident analysis API",
    version="0.2.0",
)


class AnalyzeRequest(BaseModel):
    source: str = Field(
        description="Log source: github-actions, docker, or kubernetes"
    )
    logs: str = Field(
        min_length=1,
        max_length=100_000,
        description="Raw log text to analyze",
    )


class IncidentCreateRequest(AnalyzeRequest):
    fix_description: str | None = Field(
        default=None,
        max_length=5000,
        description="Optional description of a proposed or applied fix",
    )


class FixDescriptionRequest(BaseModel):
    fix_description: str | None = Field(
        default=None,
        max_length=5000,
        description="Updated remediation notes; null clears the description",
    )


class VerificationRequest(BaseModel):
    status: Literal["not_run", "passed", "failed"]
    notes: str = Field(default="", max_length=5000)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AI DevOps Incident Assistant",
    }


@app.post("/api/v1/analyze")
def analyze(request: AnalyzeRequest):
    try:
        return analyze_log(
            source=request.source,
            log_text=request.logs,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@app.post("/api/v1/incidents", status_code=201)
def create_incident(request: IncidentCreateRequest):
    try:
        analysis = analyze_log(
            source=request.source,
            log_text=request.logs,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    return save_incident(
        source=request.source.strip().lower(),
        logs=request.logs,
        analysis=analysis,
        fix_description=request.fix_description,
    )


@app.get("/api/v1/incidents")
def get_incidents(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    return {
        "items": list_incidents(limit=limit, offset=offset),
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/v1/incidents/{incident_id}")
def get_incident_by_id(incident_id: int):
    incident = get_incident(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return incident


@app.post("/api/v1/incidents/{incident_id}/verification")
def verify_incident(
    incident_id: int,
    request: VerificationRequest,
):
    incident = update_verification(
        incident_id=incident_id,
        status=request.status,
        notes=request.notes,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return incident


@app.put("/api/v1/incidents/{incident_id}/fix")
def update_incident_fix(
    incident_id: int,
    request: FixDescriptionRequest,
):
    incident = update_fix_description(
        incident_id=incident_id,
        fix_description=request.fix_description,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return incident

