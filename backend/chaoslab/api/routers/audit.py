"""Audit log query and hash-chain verification endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from chaoslab.api.schemas import AuditEventOut, AuditListResponse, AuditVerifyResponse
from chaoslab.audit import service as audit_svc
from chaoslab.auth.dependencies import require
from chaoslab.auth.models import User
from chaoslab.auth.permissions import Permission
from chaoslab.db.base import to_utc_iso
from chaoslab.db.session import get_db

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditListResponse)
def list_audit_events(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.AUDIT_READ))],
    action: str | None = Query(default=None, max_length=128),
    actor: str | None = Query(default=None, max_length=255),
    subject_type: str | None = Query(default=None, max_length=64),
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    search: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AuditListResponse:
    items, total = audit_svc.list_events(
        db,
        action=action,
        actor=actor,
        subject_type=subject_type,
        since=since,
        until=until,
        search=search,
        limit=limit,
        offset=offset,
    )
    return AuditListResponse(
        total=total,
        items=[
            AuditEventOut(
                seq=ev.seq,
                at=to_utc_iso(ev.at),
                actor_user_id=ev.actor_user_id,
                actor_email=ev.actor_email,
                action=ev.action,
                subject_type=ev.subject_type,
                subject_id=ev.subject_id,
                details=dict(ev.details or {}),
                prev_hash=ev.prev_hash,
                hash=ev.hash,
            )
            for ev in items
        ],
    )


@router.get("/verify", response_model=AuditVerifyResponse)
def verify_audit_chain(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.ADMIN_SETTINGS))],
) -> AuditVerifyResponse:
    res = audit_svc.verify_chain(db)
    return AuditVerifyResponse(**res)
