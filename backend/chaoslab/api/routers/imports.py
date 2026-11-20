"""Imports (validate/commit/history) and formula-safe inventory export endpoints."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from chaoslab.api.schemas import ImportBatchSummary, ImportReportResponse
from chaoslab.auth.dependencies import get_settings_dep, require
from chaoslab.auth.models import User
from chaoslab.auth.permissions import Permission
from chaoslab.config import Settings
from chaoslab.db.session import get_db
from chaoslab.imports import service as imp_svc
from chaoslab.inventory import service as inv_svc

router = APIRouter(tags=["imports"])


async def _handle_import(
    *,
    env_id: str,
    commit: bool,
    file: UploadFile,
    fmt: str,
    entity_type: str | None,
    vantage_zone_key: str,
    target_zone_key: str,
    db: Session,
    user: User,
    settings: Settings,
) -> dict:
    raw_bytes = await file.read(settings.max_upload_bytes + 1)
    try:
        return imp_svc.process_import(
            db,
            env_id=env_id,
            fmt=fmt,
            raw_bytes=raw_bytes,
            filename=file.filename,
            actor_email=user.email,
            actor_user_id=user.id,
            commit=commit,
            settings=settings,
            entity_type=entity_type,
            vantage_zone_key=vantage_zone_key,
            target_zone_key=target_zone_key,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/environments/{env_id}/imports/validate", response_model=ImportReportResponse)
async def validate_import_endpoint(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.IMPORTS_WRITE))],
    settings: Annotated[Settings, Depends(get_settings_dep)],
    file: Annotated[UploadFile, File(...)],
    fmt: Annotated[str, Form(alias="format")],
    entity_type: Annotated[str | None, Form()] = None,
    vantage_zone_key: Annotated[str, Form()] = "internet",
    target_zone_key: Annotated[str, Form()] = "dmz",
) -> ImportReportResponse:
    report = await _handle_import(
        env_id=env_id,
        commit=False,
        file=file,
        fmt=fmt,
        entity_type=entity_type,
        vantage_zone_key=vantage_zone_key,
        target_zone_key=target_zone_key,
        db=db,
        user=user,
        settings=settings,
    )
    return ImportReportResponse(**report)


@router.post("/environments/{env_id}/imports/commit", response_model=ImportReportResponse)
async def commit_import_endpoint(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.IMPORTS_WRITE))],
    settings: Annotated[Settings, Depends(get_settings_dep)],
    file: Annotated[UploadFile, File(...)],
    fmt: Annotated[str, Form(alias="format")],
    entity_type: Annotated[str | None, Form()] = None,
    vantage_zone_key: Annotated[str, Form()] = "internet",
    target_zone_key: Annotated[str, Form()] = "dmz",
) -> Response | ImportReportResponse:
    report = await _handle_import(
        env_id=env_id,
        commit=True,
        file=file,
        fmt=fmt,
        entity_type=entity_type,
        vantage_zone_key=vantage_zone_key,
        target_zone_key=target_zone_key,
        db=db,
        user=user,
        settings=settings,
    )
    if report["status"] == "rejected":
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": "Import validation failed; nothing committed.", **report},
        )
    return ImportReportResponse(**report)


@router.get("/environments/{env_id}/imports", response_model=list[ImportBatchSummary])
def list_imports_endpoint(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.INVENTORY_READ))],
) -> list[ImportBatchSummary]:
    if inv_svc.get_environment(db, env_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    return [ImportBatchSummary(**b) for b in imp_svc.list_import_batches(db, env_id)]


@router.get("/environments/{env_id}/export/json")
def export_json_endpoint(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.INVENTORY_READ))],
) -> Response:
    try:
        doc = imp_svc.export_environment_json(
            db, env_id=env_id, actor_email=user.email, actor_user_id=user.id
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    body = json.dumps(doc, indent=2, sort_keys=True)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="chaoslab-env-{env_id[:8]}.json"',
        },
    )


@router.get("/environments/{env_id}/export/csv")
def export_csv_endpoint(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.INVENTORY_READ))],
    entity: str = Query(default="assets", max_length=32),
) -> Response:
    try:
        csv_text = imp_svc.export_entity_csv(
            db,
            env_id=env_id,
            entity_type=entity,
            actor_email=user.email,
            actor_user_id=user.id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="chaoslab-{entity}-{env_id[:8]}.csv"',
        },
    )
