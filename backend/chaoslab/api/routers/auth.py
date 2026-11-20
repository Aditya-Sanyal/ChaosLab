"""Authentication and current-session endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from chaoslab.api.schemas import LoginRequest, UserResponse
from chaoslab.auth.dependencies import (
    SESSION_COOKIE_NAME,
    enforce_csrf_on_mutation,
    get_current_user,
    get_settings_dep,
)
from chaoslab.auth.models import User
from chaoslab.auth.service import (
    AuthenticationError,
    RateLimitError,
    authenticate_and_create_session,
    revoke_session,
)
from chaoslab.config import Settings
from chaoslab.db.session import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


def _user_out(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        is_active=user.is_active,
    )


@router.post("/login", response_model=UserResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> UserResponse:
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")
    try:
        user, raw_token = authenticate_and_create_session(
            db,
            email=payload.email,
            password=payload.password,
            settings=settings,
            ip=client_ip,
            user_agent=user_agent,
        )
    except RateLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)
        ) from exc
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
        max_age=settings.session_absolute_days * 86400,
    )
    return _user_out(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
) -> Response:
    enforce_csrf_on_mutation(request)
    revoke_session(db, raw_token=request.cookies.get(SESSION_COOKIE_NAME))
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserResponse)
def me(user: Annotated[User, Depends(get_current_user)]) -> UserResponse:
    return _user_out(user)
