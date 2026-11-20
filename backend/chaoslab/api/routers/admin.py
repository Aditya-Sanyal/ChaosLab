"""Administrative user/role management and data-retention inspection endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from chaoslab.api.schemas import (
    AdminPasswordResetRequest,
    AdminPasswordResetResponse,
    AdminUserCreateRequest,
    AdminUserOut,
    AdminUserUpdateRequest,
    RetentionSummaryResponse,
)
from chaoslab.auth import service as auth_svc
from chaoslab.auth.dependencies import get_settings_dep, require
from chaoslab.auth.models import User
from chaoslab.auth.permissions import Permission
from chaoslab.auth.service import ConflictError
from chaoslab.config import Settings
from chaoslab.db.base import to_utc_iso
from chaoslab.db.session import get_db
from chaoslab.retention import run_retention

router = APIRouter(prefix="/admin", tags=["admin"])


def _admin_user_out(user: User, active_session_count: int) -> AdminUserOut:
    return AdminUserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,  # type: ignore[arg-type]
        is_active=user.is_active,
        active_session_count=active_session_count,
        last_login_at=to_utc_iso(user.last_login_at),
        created_at=to_utc_iso(user.created_at),
    )


@router.get("/users", response_model=list[AdminUserOut])
def list_users(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[User, Depends(require(Permission.ADMIN_USERS))],
) -> list[AdminUserOut]:
    rows = auth_svc.list_users_with_session_counts(db)
    return [_admin_user_out(u, cnt) for u, cnt in rows]


@router.post("/users", response_model=AdminUserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: AdminUserCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    admin_user: Annotated[User, Depends(require(Permission.ADMIN_USERS))],
) -> AdminUserOut:
    try:
        created = auth_svc.admin_create_user(
            db,
            email=payload.email,
            display_name=payload.display_name,
            password=payload.password,
            role=payload.role,
            is_active=payload.is_active,
            actor_user_id=admin_user.id,
            actor_email=admin_user.email,
        )
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    return _admin_user_out(created, 0)


@router.patch("/users/{user_id}", response_model=AdminUserOut)
def update_user(
    user_id: str,
    payload: AdminUserUpdateRequest,
    db: Annotated[Session, Depends(get_db)],
    admin_user: Annotated[User, Depends(require(Permission.ADMIN_USERS))],
) -> AdminUserOut:
    try:
        updated = auth_svc.admin_update_user(
            db,
            user_id=user_id,
            display_name=payload.display_name,
            role=payload.role,
            is_active=payload.is_active,
            actor_user_id=admin_user.id,
            actor_email=admin_user.email,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    rows = auth_svc.list_users_with_session_counts(db)
    count = next((cnt for u, cnt in rows if u.id == updated.id), 0)
    return _admin_user_out(updated, count)


@router.post("/users/{user_id}/reset-password", response_model=AdminPasswordResetResponse)
def reset_user_password(
    user_id: str,
    payload: AdminPasswordResetRequest,
    db: Annotated[Session, Depends(get_db)],
    admin_user: Annotated[User, Depends(require(Permission.ADMIN_USERS))],
) -> AdminPasswordResetResponse:
    try:
        updated, revoked = auth_svc.admin_reset_password(
            db,
            user_id=user_id,
            new_password=payload.new_password,
            actor_user_id=admin_user.id,
            actor_email=admin_user.email,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    return AdminPasswordResetResponse(
        user_id=updated.id,
        email=updated.email,
        sessions_revoked=revoked,
    )


@router.get("/retention-policy", response_model=RetentionSummaryResponse)
def get_retention_policy_preview(
    _request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
    admin_user: Annotated[User, Depends(require(Permission.ADMIN_SETTINGS))],
) -> RetentionSummaryResponse:
    summary = run_retention(db, settings=settings, dry_run=True, actor=admin_user.email)
    return RetentionSummaryResponse(**summary)
