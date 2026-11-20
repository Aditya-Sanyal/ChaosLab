"""FastAPI dependencies enforcing authentication, CSRF defense-in-depth, and RBAC."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from chaoslab.auth.models import User
from chaoslab.auth.permissions import Permission, has_permission
from chaoslab.auth.service import resolve_session_user
from chaoslab.config import Settings
from chaoslab.db.session import get_db

SESSION_COOKIE_NAME = "chaoslab_session"
CSRF_HEADER_NAME = "X-Requested-With"
CSRF_HEADER_VALUE = "chaoslab"


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> User:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    resolved = resolve_session_user(db, raw_token=raw_token, settings=settings)
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    user, _ = resolved
    return user


def enforce_csrf_on_mutation(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    header_val = request.headers.get(CSRF_HEADER_NAME)
    if header_val != CSRF_HEADER_VALUE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing or invalid {CSRF_HEADER_NAME} header.",
        )


def require(permission: Permission) -> Callable[..., User]:
    """Return a FastAPI dependency requiring authentication, CSRF header on writes, and RBAC."""

    def _dependency(
        request: Request,
        user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        enforce_csrf_on_mutation(request)
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission {permission.value} is required.",
            )
        return user

    return _dependency
