import os
from collections import deque
from threading import Lock
from time import monotonic
from typing import Literal

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.security import APIKeyCookie
from pydantic import BaseModel, Field

from app.services.auth_store import (
    authenticate_user,
    create_session,
    delete_session,
    get_session_user,
    get_session_user_id,
)
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
    version="0.3.0",
)

SESSION_COOKIE = "incident_session"
SESSION_MAX_AGE = 8 * 60 * 60
cookie_scheme = APIKeyCookie(
    name=SESSION_COOKIE,
    auto_error=False,
)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


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


LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_FAILURES = 5
_login_failures: dict[str, deque[float]] = {}
_login_failures_lock = Lock()


def _login_client_key(request: Request) -> str:
    # Use the direct peer address; do not trust client-supplied forwarding headers.
    return request.client.host if request.client else "unknown"


def check_login_rate_limit(request: Request) -> str:
    key = _login_client_key(request)
    now = monotonic()
    with _login_failures_lock:
        attempts = _login_failures.setdefault(key, deque())
        while attempts and now - attempts[0] >= LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= LOGIN_MAX_FAILURES:
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Try again in 15 minutes.",
                headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)},
            )
    return key


def record_failed_login(key: str) -> None:
    with _login_failures_lock:
        _login_failures.setdefault(key, deque()).append(monotonic())


def clear_login_failures(key: str) -> None:
    with _login_failures_lock:
        _login_failures.pop(key, None)


def validate_request_origin(request: Request) -> None:
    """Reject cross-origin browser requests when an Origin header is supplied."""
    origin = request.headers.get("origin")
    if not origin:
        return

    expected_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
    if origin.rstrip("/") != expected_origin.rstrip("/"):
        raise HTTPException(status_code=403, detail="Invalid request origin")


def require_user(
    request: Request,
    token: str | None = Depends(cookie_scheme),
) -> str:
    validate_request_origin(request)

    username = get_session_user(token or "")
    if username is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please log in.",
        )
    return username


def require_user_id(
    request: Request,
    token: str | None = Depends(cookie_scheme),
) -> int:
    validate_request_origin(request)

    user_id = get_session_user_id(token or "")
    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please log in.",
        )
    return user_id


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AI DevOps Incident Assistant",
    }


@app.post("/api/v1/auth/login")
def login(request: Request, payload: LoginRequest, response: Response):
    validate_request_origin(request)
    client_key = check_login_rate_limit(request)

    user_id = authenticate_user(payload.username, payload.password)
    if user_id is None:
        record_failed_login(client_key)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    clear_login_failures(client_key)
    token, _expires_at = create_session(user_id)
    secure_cookie = os.getenv("AUTH_COOKIE_SECURE", "false").lower() == "true"

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=secure_cookie,
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "username": payload.username.strip()}


@app.get("/api/v1/auth/me")
def current_session(username: str = Depends(require_user)):
    return {"authenticated": True, "username": username}


@app.post("/api/v1/auth/logout")
def logout(
    response: Response,
    token: str | None = Depends(cookie_scheme),
    _username: str = Depends(require_user),
):
    delete_session(token or "")
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=os.getenv("AUTH_COOKIE_SECURE", "false").lower() == "true",
        samesite="strict",
    )
    return {"authenticated": False}


@app.post("/api/v1/analyze")
def analyze(
    payload: AnalyzeRequest,
    _username: str = Depends(require_user),
):
    try:
        return analyze_log(source=payload.source, log_text=payload.logs)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/incidents", status_code=201)
def create_incident(
    payload: IncidentCreateRequest,
    user_id: int = Depends(require_user_id),
):
    try:
        analysis = analyze_log(
            source=payload.source,
            log_text=payload.logs,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return save_incident(
        source=payload.source.strip().lower(),
        logs=payload.logs,
        analysis=analysis,
        user_id=user_id,
        fix_description=payload.fix_description,
    )


@app.get("/api/v1/incidents")
def get_incidents(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user_id: int = Depends(require_user_id),
):
    return {
        "items": list_incidents(user_id=user_id, limit=limit, offset=offset),
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/v1/incidents/{incident_id}")
def get_incident_by_id(
    incident_id: int,
    user_id: int = Depends(require_user_id),
):
    incident = get_incident(incident_id, user_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/v1/incidents/{incident_id}/verification")
def verify_incident(
    incident_id: int,
    payload: VerificationRequest,
    user_id: int = Depends(require_user_id),
):
    incident = update_verification(
        incident_id=incident_id,
        user_id=user_id,
        status=payload.status,
        notes=payload.notes,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.put("/api/v1/incidents/{incident_id}/fix")
def update_incident_fix(
    incident_id: int,
    payload: FixDescriptionRequest,
    user_id: int = Depends(require_user_id),
):
    incident = update_fix_description(
        incident_id=incident_id,
        user_id=user_id,
        fix_description=payload.fix_description,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
