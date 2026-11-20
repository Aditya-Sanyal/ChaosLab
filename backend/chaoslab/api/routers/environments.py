"""Environments, asset inventory, asset details, topology graph, and findings endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from chaoslab.api.schemas import (
    AssetDetailResponse,
    AssetSummary,
    EnvironmentCreateRequest,
    EnvironmentOverviewResponse,
    EnvironmentSummary,
    FindingDetailResponse,
    FindingOut,
    FindingUpdateRequest,
    TopologyGraphResponse,
)
from chaoslab.auth.dependencies import require
from chaoslab.auth.models import User
from chaoslab.auth.permissions import Permission
from chaoslab.db.base import to_utc_iso
from chaoslab.db.session import get_db
from chaoslab.inventory import service as inv

router = APIRouter(prefix="/environments", tags=["environments"])


@router.get("", response_model=list[EnvironmentSummary])
def get_environments(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.INVENTORY_READ))],
) -> list[EnvironmentSummary]:
    return [
        EnvironmentSummary(
            id=e.id,
            name=e.name,
            description=e.description,
            is_demo=e.is_demo,
            created_at=to_utc_iso(e.created_at),
        )
        for e in inv.list_environments(db)
    ]


@router.post("", response_model=EnvironmentSummary, status_code=status.HTTP_201_CREATED)
def create_environment_endpoint(
    payload: EnvironmentCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.ENVIRONMENTS_MANAGE))],
) -> EnvironmentSummary:
    try:
        env = inv.create_environment(
            db,
            name=payload.name,
            description=payload.description,
            actor_email=user.email,
            actor_user_id=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return EnvironmentSummary(
        id=env.id,
        name=env.name,
        description=env.description,
        is_demo=env.is_demo,
        created_at=to_utc_iso(env.created_at),
    )


@router.get("/{env_id}/overview", response_model=EnvironmentOverviewResponse)
def get_overview(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.INVENTORY_READ))],
) -> EnvironmentOverviewResponse:
    overview = inv.get_environment_overview(db, env_id)
    if overview is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    return EnvironmentOverviewResponse(**overview)


@router.get("/{env_id}/assets", response_model=list[AssetSummary])
def get_assets(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.INVENTORY_READ))],
    search: str | None = Query(default=None, max_length=128),
    zone_key: str | None = Query(default=None, max_length=128),
    asset_type: str | None = Query(default=None, max_length=64),
    min_criticality: int | None = Query(default=None, ge=1, le=5),
    origin: str | None = Query(default=None, max_length=32),
    internet_exposed: bool | None = Query(default=None),
    has_findings: bool | None = Query(default=None),
) -> list[AssetSummary]:
    if inv.get_environment(db, env_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    rows = inv.list_assets(
        db,
        env_id,
        search=search,
        zone_key=zone_key,
        asset_type=asset_type,
        min_criticality=min_criticality,
        origin=origin,
        internet_exposed=internet_exposed,
        has_findings=has_findings,
    )
    return [AssetSummary(**r) for r in rows]


@router.get("/{env_id}/assets/{asset_key}", response_model=AssetDetailResponse)
def get_asset(
    env_id: str,
    asset_key: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.INVENTORY_READ))],
) -> AssetDetailResponse:
    if inv.get_environment(db, env_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    detail = inv.get_asset_detail(db, env_id, asset_key)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    return AssetDetailResponse(**detail)


@router.get("/{env_id}/graph", response_model=TopologyGraphResponse)
def get_graph(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.INVENTORY_READ))],
) -> TopologyGraphResponse:
    graph = inv.get_topology_graph(db, env_id)
    if graph is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    return TopologyGraphResponse(**graph)


@router.get("/{env_id}/findings", response_model=list[FindingOut])
def get_findings(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.FINDINGS_READ))],
    severity: str | None = Query(default=None, max_length=32),
    status_filter: str | None = Query(default=None, alias="status", max_length=32),
    category: str | None = Query(default=None, max_length=64),
    search: str | None = Query(default=None, max_length=128),
) -> list[FindingOut]:
    if inv.get_environment(db, env_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    rows = inv.list_findings(
        db, env_id, severity=severity, status=status_filter, category=category, search=search
    )
    return [FindingOut(**r) for r in rows]


@router.get("/{env_id}/findings/{finding_key}", response_model=FindingDetailResponse)
def get_finding_detail_endpoint(
    env_id: str,
    finding_key: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.FINDINGS_READ))],
) -> FindingDetailResponse:
    if inv.get_environment(db, env_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    detail = inv.get_finding_detail(db, env_id, finding_key)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return FindingDetailResponse(**detail)


@router.patch("/{env_id}/findings/{finding_key}", response_model=FindingDetailResponse)
def update_finding_endpoint(
    env_id: str,
    finding_key: str,
    payload: FindingUpdateRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.FINDINGS_WRITE))],
) -> FindingDetailResponse:
    if inv.get_environment(db, env_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    try:
        updated = inv.update_finding(
            db,
            env_id=env_id,
            finding_key=finding_key,
            status=payload.status,
            remediation_notes=payload.remediation_notes,
            comment=payload.comment,
            asset_status_overrides=(
                [o.model_dump() for o in payload.asset_status_overrides]
                if payload.asset_status_overrides is not None
                else None
            ),
            actor_email=user.email,
            actor_user_id=user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return FindingDetailResponse(**updated)
