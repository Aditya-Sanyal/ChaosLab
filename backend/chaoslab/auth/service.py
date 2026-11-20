"""Authentication and session lifecycle services."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from chaoslab.audit.service import record_event
from chaoslab.auth.models import User, UserSession
from chaoslab.auth.permissions import Role
from chaoslab.auth.security import (
    check_and_record_login_attempt,
    clear_login_attempts,
    generate_session_token,
    hash_password,
    hash_session_token,
    validate_password_strength,
    verify_password,
)
from chaoslab.config import Settings
from chaoslab.db.base import utcnow


class AuthenticationError(Exception):
    """Raised when credentials are invalid."""


class RateLimitError(Exception):
    """Raised when login throttling triggers."""


class ConflictError(Exception):
    """Raised when an administrative state change conflicts with invariants."""


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def create_user(
    db: Session,
    *,
    email: str,
    display_name: str,
    password: str,
    role: str,
    is_active: bool = True,
) -> User:
    user = User(
        email=email.strip().lower(),
        display_name=display_name,
        password_hash=hash_password(password),
        role=role,
        is_active=is_active,
    )
    db.add(user)
    db.flush()
    return user


def authenticate_and_create_session(
    db: Session,
    *,
    email: str,
    password: str,
    settings: Settings,
    ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[User, str]:
    normalized_email = email.strip().lower()
    rate_key = f"{ip or 'local'}:{normalized_email}"
    if not check_and_record_login_attempt(
        rate_key,
        max_attempts=settings.login_rate_limit_max_attempts,
        window_seconds=settings.login_rate_limit_window_seconds,
    ):
        record_event(
            db,
            action="auth.login_failed",
            subject_type="user",
            subject_id=normalized_email,
            details={"reason": "rate_limited", "ip": ip},
        )
        db.commit()
        raise RateLimitError("Too many login attempts; try again later.")

    user = db.execute(select(User).where(User.email == normalized_email)).scalar_one_or_none()
    if user is None or not user.is_active or not verify_password(user.password_hash, password):
        record_event(
            db,
            action="auth.login_failed",
            subject_type="user",
            subject_id=normalized_email,
            actor_user_id=user.id if user else None,
            actor_email=normalized_email,
            details={"reason": "invalid_credentials", "ip": ip},
        )
        db.commit()
        raise AuthenticationError("Invalid email or password.")

    clear_login_attempts(rate_key)
    raw_token = generate_session_token()
    now = utcnow()
    session = UserSession(
        user_id=user.id,
        token_sha256=hash_session_token(raw_token),
        created_at=now,
        expires_at=now + timedelta(days=settings.session_absolute_days),
        last_seen_at=now,
        ip=ip,
        user_agent=user_agent[:512] if user_agent else None,
    )
    user.last_login_at = now
    db.add(session)
    record_event(
        db,
        action="auth.login",
        subject_type="user",
        subject_id=user.id,
        actor_user_id=user.id,
        actor_email=user.email,
        details={"role": user.role, "ip": ip},
    )
    db.commit()
    return user, raw_token


def resolve_session_user(
    db: Session,
    *,
    raw_token: str | None,
    settings: Settings,
) -> tuple[User, UserSession] | None:
    if not raw_token:
        return None
    token_hash = hash_session_token(raw_token)
    session = db.execute(
        select(UserSession).where(UserSession.token_sha256 == token_hash)
    ).scalar_one_or_none()
    if session is None:
        return None

    now = utcnow()
    if _as_utc(session.expires_at) <= now:
        db.delete(session)
        db.commit()
        return None

    idle_deadline = _as_utc(session.last_seen_at) + timedelta(hours=settings.session_idle_hours)
    if idle_deadline <= now:
        db.delete(session)
        db.commit()
        return None

    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        return None

    session.last_seen_at = now
    db.commit()
    return user, session


def revoke_session(db: Session, *, raw_token: str | None) -> None:
    if not raw_token:
        return
    token_hash = hash_session_token(raw_token)
    session = db.execute(
        select(UserSession).where(UserSession.token_sha256 == token_hash)
    ).scalar_one_or_none()
    if session is None:
        return
    user = db.get(User, session.user_id)
    db.delete(session)
    record_event(
        db,
        action="auth.logout",
        subject_type="user",
        subject_id=session.user_id,
        actor_user_id=user.id if user else session.user_id,
        actor_email=user.email if user else None,
        details={},
    )
    db.commit()


def _validate_email_address(email: str) -> str:
    clean = email.strip().lower()
    if not clean or " " in clean or len(clean) > 255 or clean.count("@") != 1:
        raise ValueError("Provide a valid email address.")
    local, domain = clean.split("@", 1)
    if (
        not local
        or not domain
        or "." not in domain
        or domain.startswith(".")
        or domain.endswith(".")
    ):
        raise ValueError("Provide a valid email address.")
    return clean


def _revoke_user_sessions(db: Session, user_id: str) -> int:
    sessions = list(
        db.execute(select(UserSession).where(UserSession.user_id == user_id)).scalars().all()
    )
    for sess in sessions:
        db.delete(sess)
    return len(sessions)


def list_users_with_session_counts(db: Session) -> list[tuple[User, int]]:
    users = list(db.execute(select(User).order_by(User.created_at.asc())).scalars().all())
    now = utcnow()
    active_counts: dict[str, int] = {}
    session_rows = db.execute(select(UserSession.user_id, UserSession.expires_at)).all()
    for user_id, expires_at in session_rows:
        if _as_utc(expires_at) > now:
            active_counts[user_id] = active_counts.get(user_id, 0) + 1
    return [(u, active_counts.get(u.id, 0)) for u in users]


def admin_create_user(
    db: Session,
    *,
    email: str,
    display_name: str,
    password: str,
    role: str,
    is_active: bool = True,
    actor_user_id: str | None = None,
    actor_email: str,
) -> User:
    clean_email = _validate_email_address(email)
    clean_name = display_name.strip()
    if not clean_name:
        raise ValueError("Display name cannot be empty.")
    try:
        parsed_role = Role(role)
    except ValueError as exc:
        raise ValueError(f"Unsupported role '{role}'.") from exc
    validate_password_strength(password)

    existing = db.execute(select(User.id).where(User.email == clean_email)).first()
    if existing is not None:
        raise ConflictError(f"User '{clean_email}' already exists.")

    user = create_user(
        db,
        email=clean_email,
        display_name=clean_name,
        password=password,
        role=parsed_role.value,
        is_active=is_active,
    )
    record_event(
        db,
        action="admin.user_created",
        subject_type="user",
        subject_id=user.id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        details={
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
        },
    )
    db.commit()
    return user


def admin_update_user(
    db: Session,
    *,
    user_id: str,
    display_name: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    actor_user_id: str | None = None,
    actor_email: str,
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise LookupError(f"User '{user_id}' not found.")

    next_role = user.role
    if role is not None:
        try:
            next_role = Role(role).value
        except ValueError as exc:
            raise ValueError(f"Unsupported role '{role}'.") from exc

    next_active = user.is_active if is_active is None else bool(is_active)

    if user.role == Role.ADMIN.value and user.is_active and (
        next_role != Role.ADMIN.value or not next_active
    ):
        active_admins = int(
            db.execute(
                select(func.count(User.id)).where(
                    User.role == Role.ADMIN.value, User.is_active.is_(True)
                )
            ).scalar_one()
        )
        if active_admins <= 1:
            raise ConflictError("Cannot demote or disable the last active administrator.")

    before: dict[str, object] = {}
    after: dict[str, object] = {}

    if display_name is not None:
        clean_name = display_name.strip()
        if not clean_name:
            raise ValueError("Display name cannot be empty.")
        if clean_name != user.display_name:
            before["display_name"] = user.display_name
            after["display_name"] = clean_name
            user.display_name = clean_name

    if next_role != user.role:
        before["role"] = user.role
        after["role"] = next_role
        user.role = next_role

    revoked_sessions = 0
    if next_active != user.is_active:
        before["is_active"] = user.is_active
        after["is_active"] = next_active
        user.is_active = next_active
        if not next_active:
            revoked_sessions = _revoke_user_sessions(db, user.id)

    if after:
        record_event(
            db,
            action="admin.user_updated",
            subject_type="user",
            subject_id=user.id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            details={
                "email": user.email,
                "before": before,
                "after": after,
                "sessions_revoked": revoked_sessions,
            },
        )
        db.commit()
    return user


def admin_reset_password(
    db: Session,
    *,
    user_id: str,
    new_password: str,
    actor_user_id: str | None = None,
    actor_email: str,
) -> tuple[User, int]:
    user = db.get(User, user_id)
    if user is None:
        raise LookupError(f"User '{user_id}' not found.")

    validate_password_strength(new_password)
    user.password_hash = hash_password(new_password)
    revoked = _revoke_user_sessions(db, user.id)

    record_event(
        db,
        action="admin.password_reset",
        subject_type="user",
        subject_id=user.id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        details={"email": user.email, "sessions_revoked": revoked},
    )
    db.commit()
    return user, revoked
