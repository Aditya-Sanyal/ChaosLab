"""Health and database-backed readiness check endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from chaoslab import __version__
from chaoslab.api.schemas import HealthResponse, ReadinessResponse
from chaoslab.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="chaoslab-api",
        version=__version__,
        mode="offline_simulation",
    )


@router.get("/health/ready", response_model=ReadinessResponse)
def readiness(db: Annotated[Session, Depends(get_db)]) -> ReadinessResponse:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connectivity check failed.",
        ) from exc
    return ReadinessResponse(
        status="ready",
        database="ok",
        service="chaoslab-api",
        version=__version__,
        mode="offline_simulation",
    )
