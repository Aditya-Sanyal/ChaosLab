"""Immutable snapshot creation and retrieval endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from chaoslab.api.schemas import SnapshotCreateRequest, SnapshotDetail, SnapshotSummary
from chaoslab.auth.dependencies import require
from chaoslab.auth.models import User
from chaoslab.auth.permissions import Permission
from chaoslab.db.base import to_utc_iso
from chaoslab.db.session import get_db
from chaoslab.inventory.service import get_environment
from chaoslab.snapshots.models import Snapshot
from chaoslab.snapshots.repository import SqlGraphRepository

router = APIRouter(tags=["snapshots"])


def _summary(snap: Snapshot) -> SnapshotSummary:
    return SnapshotSummary(
        id=snap.id,
        environment_id=snap.environment_id,
        label=snap.label,
        sha256=snap.sha256,
        counts=dict(snap.counts or {}),
        created_by=snap.created_by,
        created_at=to_utc_iso(snap.created_at),
    )


@router.get("/environments/{env_id}/snapshots", response_model=list[SnapshotSummary])
def list_snapshots(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.SCENARIOS_READ))],
) -> list[SnapshotSummary]:
    if get_environment(db, env_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    snaps = list(
        db.execute(
            select(Snapshot)
            .where(Snapshot.environment_id == env_id)
            .order_by(Snapshot.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [_summary(s) for s in snaps]


@router.post(
    "/environments/{env_id}/snapshots",
    response_model=SnapshotSummary,
    status_code=status.HTTP_201_CREATED,
)
def create_snapshot(
    env_id: str,
    payload: SnapshotCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.SNAPSHOTS_CREATE))],
) -> SnapshotSummary:
    repo = SqlGraphRepository(db)
    try:
        snap = repo.create_snapshot(
            env_id,
            created_by=user.email,
            actor_user_id=user.id,
            label=payload.label,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return _summary(snap)


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotDetail)
def get_snapshot(
    snapshot_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.SCENARIOS_READ))],
) -> SnapshotDetail:
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot not found.")
    return SnapshotDetail(
        **_summary(snap).model_dump(),
        document=snap.document,
    )
